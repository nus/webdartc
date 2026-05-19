// Builds `webdartc_vp8.dll` and `webdartc_vp9.dll` for one Windows triplet
// by installing libvpx via vcpkg's manifest mode and compiling each wrapper
// with MSVC `cl.exe -LD` against the resulting `vpx.lib`.
//
// Shared by:
//   - .github/workflows/build-libvpx-prebuilt.yaml  (CI release prebuilt)
//   - dart/hook/build.dart                          (end-user source-build
//                                                    opt-in, Windows)
//
// Caller's responsibility before invoking:
//   - MSVC cl + link in PATH (vcvarsall.bat or ilammy/msvc-dev-cmd).
//   - vcpkg in PATH (or pass --vcpkg=<path>).
//
// No `package:` imports (only `dart:io` and the sibling `wrapper_build_env.dart`)
// so `dart run` works without `dart pub get`.
//
// Usage:
//   dart run dart/tool/build_libvpx_wrappers.dart \
//     --triplet=x64-windows-static \
//     --manifest-dir=dart/tool/libvpx_vcpkg \
//     --src-dir=dart/src \
//     --out-dir=staging

import 'dart:io';

import 'wrapper_build_env.dart';

Future<void> main(List<String> args) async {
  final opts = _parseArgs(args);

  final manifestDir = Directory(opts['manifest-dir']!).absolute;
  final srcDir = Directory(opts['src-dir']!).absolute;
  final outDir = Directory(opts['out-dir']!).absolute;
  final triplet = opts['triplet']!;
  final vcpkg = opts['vcpkg'] ?? 'vcpkg';

  await outDir.create(recursive: true);

  // 1. Install libvpx into the manifest-relative vcpkg_installed/<triplet>/.
  await _run(vcpkg, ['install', '--triplet=$triplet'],
      workingDirectory: manifestDir.path,
      desc: 'vcpkg install ($triplet)');

  final vpxRoot =
      Directory.fromUri(manifestDir.uri.resolve('vcpkg_installed/$triplet/'));
  final vpxLib = File.fromUri(vpxRoot.uri.resolve('lib/vpx.lib')).path;
  final vpxInclude = Directory.fromUri(vpxRoot.uri.resolve('include/')).path;

  // 2. cl -LD produces a DLL directly from one wrapper TU + vpx.lib. -MT
  //    keeps the CRT static (no msvcr*.dll runtime dep alongside the
  //    shipped DLL); -utf-8 silences the codepage warning on UTF-8 sources;
  //    -O2 is release optimisation.
  // vp8 and vp9 share read-only inputs (vpx.lib, headers) and write
  // disjoint outputs (webdartc_vp{8,9}.{dll,obj,exp,lib}) — run them in
  // parallel.
  await Future.wait([
    for (final codec in const ['vp8', 'vp9'])
      _run('cl', [
        '-nologo',
        '-LD',
        '-MT',
        '-O2',
        '-utf-8',
        '-I${srcDir.path}',
        '-I$vpxInclude',
        '-Fe:${File.fromUri(outDir.uri.resolve('webdartc_$codec.dll')).path}',
        File.fromUri(srcDir.uri.resolve('webdartc_$codec.c')).path,
        vpxLib,
      ], workingDirectory: outDir.path, desc: 'cl -LD webdartc_$codec.dll'),
  ]);

  // 3. cl -LD writes its .obj / .exp / import .lib alongside the .dll in
  //    CWD. We only ship the DLL.
  for (final entry in outDir.listSync()) {
    if (entry is! File) continue;
    final name = entry.uri.pathSegments.last.toLowerCase();
    final ship = name.endsWith('.dll') ||
        name == 'license' ||
        name == 'license.txt' ||
        name == 'notice.txt';
    if (!ship) entry.deleteSync();
  }

  stdout.writeln(
      'OK: webdartc_vp8.dll + webdartc_vp9.dll under ${outDir.path}');
}

Map<String, String> _parseArgs(List<String> args) {
  const required = {'triplet', 'manifest-dir', 'src-dir', 'out-dir'};
  const optional = {'vcpkg'};
  final out = <String, String>{};
  for (final a in args) {
    if (!a.startsWith('--')) {
      _die('unexpected positional argument: $a');
    }
    final eq = a.indexOf('=');
    if (eq < 0) _die('expected --key=value, got: $a');
    final key = a.substring(2, eq);
    if (!required.contains(key) && !optional.contains(key)) {
      _die('unknown option: --$key');
    }
    out[key] = a.substring(eq + 1);
  }
  for (final k in required) {
    if (!out.containsKey(k)) _die('missing required arg: --$k');
  }
  return out;
}

Never _die(String msg) {
  stderr.writeln('build_libvpx_wrappers: $msg');
  exit(64);
}

Future<void> _run(String exe, List<String> args,
    {String? workingDirectory, required String desc}) async {
  stdout.writeln('[run] $desc');
  stdout.writeln('+ $exe ${args.join(' ')}');
  final proc = await Process.start(exe, args,
      workingDirectory: workingDirectory,
      runInShell: false,
      environment: _childEnv);
  final stdoutDone = proc.stdout.listen(stdout.add).asFuture<void>();
  final stderrDone = proc.stderr.listen(stderr.add).asFuture<void>();
  final exitCode = await proc.exitCode;
  await Future.wait([stdoutDone, stderrDone]);
  if (exitCode != 0) {
    throw StateError('$desc failed (exit $exitCode)');
  }
}

final Map<String, String> _childEnv = buildWrapperChildEnv();
