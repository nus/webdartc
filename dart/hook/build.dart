// Build hook for webdartc native code assets.
//
// Apple platforms (macOS / iOS): compile the VideoToolbox callback shim.
// macOS + Linux: vendor-build libopus and link it into a single
// `webdartc_codecs` shared library alongside the `webdartc_opus_*`
// wrapper. Only the wrapper symbols are exported (`-fvisibility=hidden`
// plus per-function `visibility("default")` in webdartc_opus.h), so
// libopus's own `opus_*` symbols cannot collide with another libopus
// loaded into the same process.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final targetOS = input.config.code.targetOS;

    // The two builds are independent (distinct asset names + cmake dirs);
    // running them concurrently overlaps the cmake configure with the VT
    // shim compile.
    await Future.wait([
      if (targetOS == OS.macOS || targetOS == OS.iOS)
        _buildVtCallback(input, output),
      if (targetOS == OS.macOS || targetOS == OS.linux)
        _buildOpusCodecs(input, output),
    ]);
  });
}

Future<void> _buildVtCallback(
    BuildInput input, BuildOutputBuilder output) async {
  // CBuilder only emits `-framework X` when language is Objective-C, so we
  // pass framework flags directly for a plain-C shim.
  const frameworks = [
    'CoreFoundation',
    'CoreVideo',
    'CoreMedia',
    'VideoToolbox',
  ];
  final builder = CBuilder.library(
    name: 'wvt_callback',
    assetName: 'codec/h264/videotoolbox/wvt_callback.dart',
    sources: ['src/wvt_callback.c'],
    flags: [for (final f in frameworks) ...['-framework', f]],
  );
  await builder.run(input: input, output: output);
}

// CMake on Linux installs to lib/ on Debian/Ubuntu but lib64/ on some
// distros; libopus's own CMakeLists honours GNUInstallDirs. Probe both.
const _libopusArchiveCandidates = ['lib/libopus.a', 'lib64/libopus.a'];

Future<void> _buildOpusCodecs(
    BuildInput input, BuildOutputBuilder output) async {
  final (opusInstall, libopusA) = await _cmakeBuildOpus(input);
  final includeDir = opusInstall.resolve('include/opus/').toFilePath();

  final targetOS = input.config.code.targetOS;
  final builder = CBuilder.library(
    name: 'webdartc_codecs',
    assetName: 'codec/opus/webdartc_opus.dart',
    sources: ['src/webdartc_opus.c'],
    includes: [includeDir],
    flags: [
      // Hide every symbol by default so libopus's `opus_*` body stays
      // internal. Only the wrapper functions (annotated with
      // visibility("default") in webdartc_opus.h) get exported.
      '-fvisibility=hidden',
      // CBuilder emits flags BEFORE source files. macOS `ld64` rescans
      // archives so order doesn't matter, but Linux `ld` is single-pass
      // and skips an archive that precedes its referencing objects.
      // `--whole-archive` forces every member to be linked regardless of
      // position; hidden visibility still keeps the symbols internal.
      if (targetOS == OS.linux) '-Wl,--whole-archive',
      libopusA,
      if (targetOS == OS.linux) '-Wl,--no-whole-archive',
    ],
  );
  await builder.run(input: input, output: output);
}

String? _findArchive(Uri prefix) {
  for (final rel in _libopusArchiveCandidates) {
    final p = prefix.resolve(rel).toFilePath();
    if (File(p).existsSync()) return p;
  }
  return null;
}

/// Configure + build libopus into a static archive, returning the install
/// prefix URI (with `include/opus/*.h`) plus the resolved archive path.
///
/// Cached under [BuildInput.outputDirectoryShared] so successive builds
/// reuse the cmake build tree (libopus rebuild is ~30 s otherwise). Wipe
/// `.dart_tool/hooks_runner/shared/webdartc/build/opus-*` after a
/// `git submodule update` to pick up source changes.
Future<(Uri, String)> _cmakeBuildOpus(BuildInput input) async {
  final arch = switch (input.config.code.targetArchitecture) {
    Architecture.arm64 => 'arm64',
    Architecture.x64 => 'x86_64',
    final a => throw UnsupportedError('libopus build: unsupported arch $a'),
  };
  final targetOS = input.config.code.targetOS;
  final shared = input.outputDirectoryShared;
  final buildDir = Directory.fromUri(shared.resolve('opus-build-$arch/'));
  final installDir = Directory.fromUri(shared.resolve('opus-install-$arch/'));
  final cached = _findArchive(installDir.uri);
  if (cached != null) return (installDir.uri, cached);

  await buildDir.create(recursive: true);
  final src = input.packageRoot.resolve('third_party/opus/').toFilePath();
  await _runChecked('cmake', [
    '-S', src,
    '-B', buildDir.path,
    '-DCMAKE_BUILD_TYPE=Release',
    '-DBUILD_SHARED_LIBS=OFF',
    '-DOPUS_BUILD_PROGRAMS=OFF',
    '-DOPUS_BUILD_TESTING=OFF',
    '-DOPUS_BUILD_SHARED_LIBRARY=OFF',
    '-DCMAKE_INSTALL_PREFIX=${installDir.path}',
    if (targetOS == OS.macOS) ...[
      '-DCMAKE_OSX_ARCHITECTURES=$arch',
      '-DCMAKE_OSX_DEPLOYMENT_TARGET=10.15',
    ],
    // The static archive is later linked into a shared library, so every
    // object must be position-independent. CMake doesn't enable PIC for
    // STATIC libs by default, and on Linux the linker rejects non-PIC
    // input to `-shared` with "relocation R_*_PC32 against symbol cannot
    // be used when making a shared object".
    '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
    // libopus stamps `OPUS_EXPORT = visibility("default")` on its public
    // API when OPUS_BUILD is set (which its own CMakeLists does
    // unconditionally), overriding our `-fvisibility=hidden`. Pre-define
    // OPUS_EXPORT to nothing so the hidden default actually wins.
    '-DCMAKE_C_VISIBILITY_PRESET=hidden',
    '-DCMAKE_C_FLAGS=-DOPUS_EXPORT=',
  ], desc: 'libopus cmake configure');
  await _runChecked('cmake', [
    '--build', buildDir.path,
    '--target', 'install',
    '--config', 'Release',
    '--parallel',
  ], desc: 'libopus cmake build');
  final installed = _findArchive(installDir.uri);
  if (installed == null) {
    throw StateError('libopus cmake install produced none of '
        '$_libopusArchiveCandidates under ${installDir.path}');
  }
  return (installDir.uri, installed);
}

Future<void> _runChecked(String exe, List<String> args,
    {required String desc}) async {
  final r = await Process.run(exe, args);
  if (r.exitCode != 0) {
    throw StateError('$desc failed:\n${r.stdout}\n${r.stderr}');
  }
}
