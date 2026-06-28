// Regenerates the Android MediaCodec FFI bindings
// (`lib/codec/h264/mediacodec/bindings.g.dart`).
//
// `tool/ffigen_mediacodec.yaml` is a token-based template: its `@NDK_*@`
// placeholders are machine-specific absolute paths (the NDK install location
// contains a developer's `$HOME`), which must not be committed. This script
// resolves the NDK from the environment, substitutes the tokens into a
// gitignored `tool/ffigen_mediacodec.local.yaml`, runs ffigen on it, then
// removes the local copy.
//
// Run from the `dart/` package root:
//   dart run tool/gen_mediacodec_bindings.dart
//
// NDK resolution mirrors hook/build.dart's `_findAndroidNdk`: ANDROID_NDK_HOME
// / ANDROID_NDK_ROOT, else `<sdk>/ndk/<newest>` under ANDROID_HOME /
// ANDROID_SDK_ROOT / the conventional macOS + Linux SDK locations.

import 'dart:io';

void main() async {
  final ndk = _findNdk();
  if (ndk == null) {
    stderr.writeln(
        'Android NDK not found. Set ANDROID_NDK_HOME (or ANDROID_HOME) to a '
        'directory containing an installed NDK.');
    exit(1);
  }

  final host = _firstSubdir('${ndk.path}/toolchains/llvm/prebuilt',
      what: 'NDK prebuilt host toolchain');
  final clangVer = _firstSubdir('$host/lib/clang',
      what: 'clang resource directory', preferNewest: true);

  final sysroot = '$host/sysroot';
  final substitutions = {
    '@NDK_LLVM@': host,
    '@NDK_SYSROOT@': sysroot,
    '@NDK_CLANG_INC@': '$clangVer/include',
  };

  // Sanity-check the resolved paths before handing them to clang.
  for (final p in [host, sysroot, '$clangVer/include',
    '$sysroot/usr/include/media/NdkMediaCodec.h']) {
    if (!File(p).existsSync() && !Directory(p).existsSync()) {
      stderr.writeln('Resolved NDK path does not exist: $p');
      exit(1);
    }
  }

  final scriptDir = File.fromUri(Platform.script).parent.path; // tool/
  var template = File('$scriptDir/ffigen_mediacodec.yaml').readAsStringSync();
  substitutions.forEach((k, v) => template = template.replaceAll(k, v));

  // Keep the generated config in tool/ so the template's relative `output:`
  // (../lib/...) still resolves. Gitignored; removed after the run.
  final localCfg = File('$scriptDir/ffigen_mediacodec.local.yaml');
  localCfg.writeAsStringSync(template);
  stdout.writeln('Resolved NDK: ${ndk.path}');
  stdout.writeln('Running ffigen via ${localCfg.path} ...');

  try {
    final result = await Process.start(
      Platform.resolvedExecutable,
      ['run', 'ffigen', '--config', localCfg.path],
      mode: ProcessStartMode.inheritStdio,
    );
    final code = await result.exitCode;
    if (code != 0) exit(code);
  } finally {
    if (localCfg.existsSync()) localCfg.deleteSync();
  }
  stdout.writeln('Generated lib/codec/h264/mediacodec/bindings.g.dart');
}

Directory? _findNdk() {
  final env = Platform.environment;
  for (final k in ['ANDROID_NDK_HOME', 'ANDROID_NDK_ROOT']) {
    final v = env[k];
    if (v != null && Directory(v).existsSync()) return Directory(v);
  }
  final home = env['HOME'];
  final sdk = env['ANDROID_HOME'] ?? env['ANDROID_SDK_ROOT'];
  final roots = <String>[
    if (sdk != null) '$sdk/ndk',
    if (home != null) '$home/Library/Android/sdk/ndk',
    if (home != null) '$home/Android/Sdk/ndk',
  ];
  for (final r in roots) {
    final dir = Directory(r);
    if (!dir.existsSync()) continue;
    final versions = dir.listSync().whereType<Directory>().toList()
      ..sort((a, b) => a.path.compareTo(b.path));
    if (versions.isNotEmpty) return Directory(versions.last.path);
  }
  return null;
}

/// Returns the (single, or newest) immediate subdirectory of [parent].
String _firstSubdir(String parent, {required String what, bool preferNewest = false}) {
  final dir = Directory(parent);
  if (!dir.existsSync()) {
    stderr.writeln('$what not found under $parent');
    exit(1);
  }
  final subs = dir.listSync().whereType<Directory>().toList()
    ..sort((a, b) => a.path.compareTo(b.path));
  if (subs.isEmpty) {
    stderr.writeln('$what is empty under $parent');
    exit(1);
  }
  return (preferNewest ? subs.last : subs.first).path;
}
