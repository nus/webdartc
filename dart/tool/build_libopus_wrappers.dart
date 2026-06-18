// Builds `webdartc_opus.dll` for one Windows triplet by installing libopus
// via vcpkg's manifest mode and compiling the wrapper TU with MSVC
// `cl.exe -LD` against the resulting `opus.lib`.
//
// Invoked by dart/hook/build.dart's Windows codec build (the default — and
// only — path on Windows; macOS / Linux / Android build their codecs
// directly in the hook).
//
// Caller's responsibility before invoking:
//   - MSVC cl + link in PATH (vcvarsall.bat or ilammy/msvc-dev-cmd).
//   - vcpkg in PATH (or pass --vcpkg=<path>).
//
// No `package:` imports (only `dart:io` and the sibling `wrapper_build_env.dart`)
// so `dart run` works without `dart pub get`.
//
// Usage:
//   dart run dart/tool/build_libopus_wrappers.dart \
//     --triplet=x64-windows-static \
//     --manifest-dir=dart/tool/libopus_vcpkg \
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

  // 1. Install libopus into the manifest-relative vcpkg_installed/<triplet>/.
  await _run(vcpkg, ['install', '--triplet=$triplet'],
      workingDirectory: manifestDir.path,
      desc: 'vcpkg install ($triplet)');

  final opusRoot =
      Directory.fromUri(manifestDir.uri.resolve('vcpkg_installed/$triplet/'));
  final opusLib = File.fromUri(opusRoot.uri.resolve('lib/opus.lib')).path;
  final opusInclude = Directory.fromUri(opusRoot.uri.resolve('include/')).path;
  // vcpkg's opus port installs headers under `include/opus/*.h`; the
  // wrapper TU uses `#include <opus.h>` so it needs the `opus/` subdir
  // on the include path.
  final opusIncludeOpus =
      Directory.fromUri(opusRoot.uri.resolve('include/opus/')).path;

  // 2. cl -LD produces a DLL directly from the wrapper TU + opus.lib. -MT
  //    keeps the CRT static (no msvcr*.dll runtime dep alongside the
  //    shipped DLL); -utf-8 silences the codepage warning on UTF-8 sources;
  //    -O2 is release optimisation.
  await _run('cl', [
    '-nologo',
    '-LD',
    '-MT',
    '-O2',
    '-utf-8',
    '-I${srcDir.path}',
    '-I$opusInclude',
    '-I$opusIncludeOpus',
    '-Fe:${File.fromUri(outDir.uri.resolve('webdartc_opus.dll')).path}',
    File.fromUri(srcDir.uri.resolve('webdartc_opus.c')).path,
    opusLib,
  ], workingDirectory: outDir.path, desc: 'cl -LD webdartc_opus.dll');

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

  stdout.writeln('OK: webdartc_opus.dll under ${outDir.path}');
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
  stderr.writeln('build_libopus_wrappers: $msg');
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
