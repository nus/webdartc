// Build hook for webdartc native code assets.
//
// Apple platforms (macOS / iOS): compile the VideoToolbox callback shim.
// macOS + Linux: vendor-build each codec library and link it into a
// dedicated wrapper shared library:
//   - libopus  → webdartc_codecs  (exports webdartc_opus_*)
//   - libvpx   → webdartc_vp8     (exports webdartc_vp8_*)
//              → webdartc_vp9     (exports webdartc_vp9_*)
// (the libvpx static archive is built once per arch and reused across
// the VP8 / VP9 wrappers)
// Only the wrapper symbols are exported (`-fvisibility=hidden` plus
// per-function `visibility("default")` in webdartc_*.h), so the codec
// libraries' own symbols cannot collide with another copy loaded into
// the same process.
//
// Linux also bundles Cisco's prebuilt OpenH264 dylib (downloaded by
// [_bundleOpenH264]). macOS uses VideoToolbox so OpenH264 isn't shipped
// there.
//
// Windows is fully prebuilt by default — Cisco's OpenH264 plus our own
// `webdartc_vp{8,9}.dll` and `webdartc_opus.dll` bundles published from
// the matching `Build *-prebuilt` GitHub Actions workflows. Setting
// `libvpx_source_build: true` / `libopus_source_build: true` pubspec
// defines under `hooks.user_defines.webdartc` flips the corresponding
// codec to build-from-source locally via the matching
// `tool/build_lib*_wrappers.dart` (requires vcpkg + MSVC + ARM64/x64
// cl in PATH).

import 'dart:io';

import 'package:archive/archive.dart';
import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final targetOS = input.config.code.targetOS;

    // The two builds are independent (distinct asset names + cmake dirs);
    // running them concurrently overlaps the cmake configure with the VT
    // shim compile.
    await Future.wait<void>([
      if (targetOS == OS.macOS || targetOS == OS.iOS) ...[
        _buildVtCallback(input, output),
        _buildWmdMedia(input, output),
      ],
      if (targetOS == OS.macOS || targetOS == OS.linux) ...[
        _buildOpusCodecs(input, output),
        _buildVp8Codec(input, output),
        _buildVp9Codec(input, output),
      ],
      if (targetOS == OS.linux || targetOS == OS.windows)
        _bundleOpenH264(input, output),
      if (targetOS == OS.windows) ...[
        _libvpxOnWindows(input, output),
        _libopusOnWindows(input, output),
      ],
    ]);
  });
}

/// Windows: bundled `webdartc_vp{8,9}.dll` via either the published
/// prebuilt zip (default) or a local source build through
/// `tool/build_libvpx_wrappers.dart` (opt-in via
/// `hooks.user_defines.webdartc.libvpx_source_build: true` in
/// `pubspec.yaml`).
Future<void> _libvpxOnWindows(BuildInput input, BuildOutputBuilder output) =>
    _windowsSourceBuildOpt(input, 'libvpx_source_build')
        ? _buildLibvpxFromSource(input, output)
        : _bundleLibvpxPrebuilt(input, output);

/// Windows counterpart of [_libvpxOnWindows] for libopus — same
/// download-or-source-build dispatch under
/// `hooks.user_defines.webdartc.libopus_source_build`.
Future<void> _libopusOnWindows(BuildInput input, BuildOutputBuilder output) =>
    _windowsSourceBuildOpt(input, 'libopus_source_build')
        ? _buildLibopusFromSource(input, output)
        : _bundleLibopusPrebuilt(input, output);

/// Reads a `lib*_source_build` user-define, accepting both YAML boolean
/// `true` and the string `'true'` (a quoted value in pubspec.yaml would
/// silently become a String).
bool _windowsSourceBuildOpt(BuildInput input, String key) {
  final raw = input.userDefines[key];
  return raw == true || (raw is String && raw.toLowerCase() == 'true');
}

const _libvpxCodecs = ['vp8', 'vp9'];

/// Emits `CodeAsset`s for each `webdartc_vp{8,9}.dll` sitting under [dllDir].
/// Shared by the prebuilt-download and source-build paths.
void _registerLibvpxWrappers(BuildOutputBuilder output, Uri dllDir) {
  for (final codec in _libvpxCodecs) {
    output.assets.code.add(CodeAsset(
      package: 'webdartc',
      name: 'codec/$codec/webdartc_$codec.dart',
      linkMode: DynamicLoadingBundled(),
      file: dllDir.resolve('webdartc_$codec.dll'),
    ));
  }
}

/// Emits the `CodeAsset` for `webdartc_opus.dll` sitting under [dllDir].
/// Shared by the prebuilt-download and source-build paths.
void _registerLibopusWrapper(BuildOutputBuilder output, Uri dllDir) {
  output.assets.code.add(CodeAsset(
    package: 'webdartc',
    name: 'codec/opus/webdartc_opus.dart',
    linkMode: DynamicLoadingBundled(),
    file: dllDir.resolve('webdartc_opus.dll'),
  ));
}

Future<void> _buildVtCallback(BuildInput input, BuildOutputBuilder output) =>
    _buildAppleShim(
      input: input,
      output: output,
      name: 'wvt_callback',
      assetName: 'codec/h264/videotoolbox/wvt_callback.dart',
      source: 'src/wvt_callback.c',
      frameworks: const ['CoreFoundation', 'CoreVideo', 'CoreMedia', 'VideoToolbox'],
    );

Future<void> _buildWmdMedia(BuildInput input, BuildOutputBuilder output) =>
    _buildAppleShim(
      input: input,
      output: output,
      name: 'wmd_media',
      assetName: 'media/macos/avf_media.dart',
      source: 'src/wmd_media.m',
      frameworks: const [
        'Foundation', 'AVFoundation', 'CoreMedia', 'CoreVideo',
        'CoreAudio', 'AudioToolbox',
      ],
      objc: true,
    );

/// Compile a single-TU Apple-only shim into a dylib code asset. `-framework`
/// flags are passed directly because `CBuilder` only emits them when language
/// is Objective-C, and we want both plain-C and ObjC shims handled the same.
Future<void> _buildAppleShim({
  required BuildInput input,
  required BuildOutputBuilder output,
  required String name,
  required String assetName,
  required String source,
  required List<String> frameworks,
  bool objc = false,
}) async {
  final builder = CBuilder.library(
    name: name,
    assetName: assetName,
    sources: [source],
    language: objc ? Language.objectiveC : Language.c,
    flags: [
      if (objc) '-fobjc-arc',
      for (final f in frameworks) ...['-framework', f],
    ],
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
      ..._linkArchive(targetOS, libopusA),
    ],
  );
  await builder.run(input: input, output: output);
}

/// Link flags that pull every member of [archivePath] into the output
/// dylib, then prevent any of them from being auto-exported.
///
/// On Linux, `ld` is single-pass — without `--whole-archive` it would
/// discard members that aren't referenced yet by the time the archive
/// is processed (CBuilder emits flags before sources). And without
/// `--exclude-libs`, every symbol pulled in via `--whole-archive` ends
/// up in the dylib's dynamic export table regardless of source-level
/// `-fvisibility=hidden` — notably libvpx's x86 SIMD TUs are
/// assembled by yasm, which doesn't emit visibility metadata at all.
/// macOS `ld64` rescans archives and respects per-symbol visibility,
/// so neither flag is needed there.
List<String> _linkArchive(OS targetOS, String archivePath) {
  if (targetOS != OS.linux) return [archivePath];
  final basename = archivePath.split('/').last;
  return [
    '-Wl,--whole-archive',
    archivePath,
    '-Wl,--no-whole-archive',
    '-Wl,--exclude-libs,$basename',
  ];
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
  await _ensureOpusTags(src);
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

/// libopus's CMake reads its version via `git describe --tags --match "v*"`
/// against the submodule's git dir. `actions/checkout@v6 submodules:
/// recursive` clones only the pinned commit without fetching tag refs,
/// so without this the cmake configure falls back to building a "libopus
/// unknown" copy. Skip the fetch if any v* tag is already cached locally
/// — keeps offline rebuilds working and avoids a redundant network call.
///
/// Returns silently if the submodule isn't initialised (no `.git`) or if
/// the fetch fails — cmake will then build "libopus unknown" but won't
/// crash, matching the prior behaviour on offline / incomplete clones.
/// A stderr warning is emitted on fetch failure so the regression is
/// visible in CI logs instead of silent.
Future<void> _ensureOpusTags(String src) async {
  // Without this guard `git -C <src>` would walk up to the superproject's
  // git dir on a fresh clone that skipped `--recurse-submodules`, and
  // we'd tag-probe / fetch against webdartc itself.
  if (!File('$src/.git').existsSync() &&
      !Directory('$src/.git').existsSync()) {
    return;
  }
  final tagsCheck = await Process.run('git', ['-C', src, 'tag', '-l', 'v*']);
  if (tagsCheck.exitCode == 0 &&
      (tagsCheck.stdout as String).trim().isNotEmpty) {
    return;
  }
  final fetch =
      await Process.run('git', ['-C', src, 'fetch', '--tags', '--quiet']);
  if (fetch.exitCode != 0) {
    stderr.writeln('warning: git fetch --tags for libopus submodule failed '
        '(exit ${fetch.exitCode}); the resulting libopus dylib will report '
        '"libopus unknown" instead of the pinned release tag.\n'
        '${fetch.stderr}');
  }
}

Future<void> _buildVp8Codec(
    BuildInput input, BuildOutputBuilder output) async {
  await _buildLibvpxWrapper(
    input: input,
    output: output,
    name: 'webdartc_vp8',
    assetName: 'codec/vp8/webdartc_vp8.dart',
    source: 'src/webdartc_vp8.c',
  );
}

Future<void> _buildVp9Codec(
    BuildInput input, BuildOutputBuilder output) async {
  await _buildLibvpxWrapper(
    input: input,
    output: output,
    name: 'webdartc_vp9',
    assetName: 'codec/vp9/webdartc_vp9.dart',
    source: 'src/webdartc_vp9.c',
  );
}

/// Compiles a `webdartc_*` libvpx wrapper TU and links it against the
/// shared static libvpx archive. The archive itself is built once per
/// arch by [_configureMakeLibvpx] and reused across codec wrappers.
Future<void> _buildLibvpxWrapper({
  required BuildInput input,
  required BuildOutputBuilder output,
  required String name,
  required String assetName,
  required String source,
}) async {
  final (vpxInstall, libvpxA) = await _configureMakeLibvpx(input);
  final includeDir = vpxInstall.resolve('include/').toFilePath();
  final targetOS = input.config.code.targetOS;
  final builder = CBuilder.library(
    name: name,
    assetName: assetName,
    sources: [source],
    includes: [includeDir],
    flags: [
      '-fvisibility=hidden',
      ..._linkArchive(targetOS, libvpxA),
    ],
  );
  await builder.run(input: input, output: output);
}

/// In-process memoisation keyed on the resolved libvpx target tuple
/// (`arm64-darwin23-gcc`, `x86_64-linux-gcc`, …). VP8 and VP9 wrapper
/// builds run concurrently via `Future.wait` and would otherwise both
/// invoke configure+make on the same build dir, racing
/// vpx_config.c regeneration against itself ("redefinition of cfg").
final Map<String, Future<(Uri, String)>> _libvpxFutures = {};

/// Configure + build libvpx (VP8 + VP9, both encoder + decoder) into a
/// single static archive, returning the install prefix URI plus the
/// resolved archive path. Cached the same way as libopus and reused
/// across all `webdartc_vpN` wrapper builds for this arch.
Future<(Uri, String)> _configureMakeLibvpx(BuildInput input) {
  final target = _libvpxTarget(
      input.config.code.targetOS, input.config.code.targetArchitecture);
  return _libvpxFutures[target] ??= _configureMakeLibvpxOnce(input);
}

Future<(Uri, String)> _configureMakeLibvpxOnce(BuildInput input) async {
  final targetOS = input.config.code.targetOS;
  final arch = input.config.code.targetArchitecture;
  final target = _libvpxTarget(targetOS, arch);

  final shared = input.outputDirectoryShared;
  final buildDir = Directory.fromUri(shared.resolve('vpx-build-$target/'));
  final installDir = Directory.fromUri(shared.resolve('vpx-install-$target/'));
  final installed = File.fromUri(installDir.uri.resolve('lib/libvpx.a'));
  if (installed.existsSync()) return (installDir.uri, installed.path);

  await buildDir.create(recursive: true);
  final src = input.packageRoot.resolve('third_party/libvpx/').toFilePath();
  final configure = File('$src/configure');
  if (!configure.existsSync()) {
    throw StateError(
        'libvpx submodule not initialised — run `git submodule update '
        '--init dart/third_party/libvpx`');
  }
  // On macOS, pin the deployment target to match libopus
  // (CMAKE_OSX_DEPLOYMENT_TARGET=10.15). Without this, libvpx's
  // configure picks the host SDK version (e.g. 15.0 on a macOS 15
  // CI runner), and ld64 emits "object file was built for newer
  // 'macOS' version than being linked" for every .c.o on the way
  // into the wrapper dylib.
  final extraCflags = [
    '-fvisibility=hidden',
    if (targetOS == OS.macOS) '-mmacosx-version-min=10.15',
  ];
  await _runChecked('bash', [
    configure.path,
    '--target=$target',
    '--prefix=${installDir.path}',
    '--enable-static',
    '--disable-shared',
    '--enable-pic',
    '--disable-examples',
    '--disable-tools',
    '--disable-docs',
    '--disable-unit-tests',
    // Hidden visibility on every TU; webdartc_vp8.c / webdartc_vp9.c
    // re-export their own symbols via __attribute__((visibility("default"))).
    '--extra-cflags=${extraCflags.join(' ')}',
  ], desc: 'libvpx configure', workingDirectory: buildDir.path);
  await _runChecked('make', [
    '-C', buildDir.path,
    '-j${Platform.numberOfProcessors}',
    'install',
  ], desc: 'libvpx make install');
  if (!installed.existsSync()) {
    throw StateError(
        'libvpx make install produced no ${installed.path}');
  }
  return (installDir.uri, installed.path);
}

String _libvpxTarget(OS targetOS, Architecture arch) {
  if (targetOS == OS.macOS) {
    // The version-less `arm64-darwin-gcc` target defaults to iOS in
    // libvpx 1.16 (arm64+darwin was iOS-only when the tuple was added),
    // which produces a Mach-O incompatible with macOS linkers. Always
    // pick a numbered tuple — the version only affects host compiler
    // heuristics, not ABI, so the latest pinned value works on any
    // newer macOS.
    return switch (arch) {
      Architecture.arm64 => 'arm64-darwin23-gcc',
      Architecture.x64 => 'x86_64-darwin25-gcc',
      _ => throw UnsupportedError('libvpx macOS build: unsupported arch $arch'),
    };
  }
  if (targetOS == OS.linux) {
    return switch (arch) {
      Architecture.arm64 => 'arm64-linux-gcc',
      Architecture.x64 => 'x86_64-linux-gcc',
      _ => throw UnsupportedError('libvpx Linux build: unsupported arch $arch'),
    };
  }
  throw UnsupportedError('libvpx build: unsupported OS $targetOS');
}

Future<void> _runChecked(String exe, List<String> args,
    {required String desc, String? workingDirectory}) async {
  final r = await Process.run(exe, args, workingDirectory: workingDirectory);
  if (r.exitCode != 0) {
    throw StateError('$desc failed:\n${r.stdout}\n${r.stderr}');
  }
}

// ── OpenH264 ────────────────────────────────────────────────────────────
//
// Cisco distributes prebuilt OpenH264 binaries via
// `https://ciscobinary.openh264.org/` (the same channel Firefox's GMP
// auto-update uses). See https://www.openh264.org/ for the upstream
// project's distribution terms.
//
// Bumping `_openH264Version`:
//   1. Pick a version published at https://ciscobinary.openh264.org/.
//      Note: source releases on GitHub generally land first; the
//      prebuilt binary may lag by weeks.
//   2. Probe the new URLs and update the SHA for every platform in
//      `_openH264Targets` (and the version string in
//      `dart/test/codec/openh264_version_test.dart`).
//   3. Wipe `.dart_tool/hooks_runner/shared/webdartc/openh264-*/` so the
//      cached download is refetched.
const String _openH264Version = '2.5.1';

/// Per-target metadata: CDN filename pieces, the local payload name and
/// the SHA-256 of the *decompressed* binary.
class _OpenH264Target {
  /// Slug used in both the cache directory and the CDN URL
  /// (`linux64`, `linux-arm64`, `win64`).
  final String platform;

  /// CDN filename = `${cdnStem}-{version}-{platform}.{cdnSuffix}.bz2`.
  /// On Linux the SONAME version (`.7`) is embedded in `cdnSuffix`; on
  /// Windows the file is just `openh264-X.Y.Z-win64.dll.bz2`.
  final String cdnStem;
  final String cdnSuffix;

  /// Decompressed payload filename inside the cache directory. For Linux
  /// we keep Cisco's SONAME (`libopenh264.so.7`) so any tool probing the
  /// SONAME at runtime (`readelf -d`) sees the canonical name. Windows
  /// doesn't have SONAMEs, so `openh264.dll` is fine.
  final String payloadName;

  /// SHA-256 of the decompressed payload (not the .bz2 archive).
  final String sha256;

  const _OpenH264Target({
    required this.platform,
    required this.cdnStem,
    required this.cdnSuffix,
    required this.payloadName,
    required this.sha256,
  });

  String get cdnUrl => 'https://ciscobinary.openh264.org/'
      '$cdnStem-$_openH264Version-$platform.$cdnSuffix.bz2';
}

const _openH264TargetLinuxX64 = _OpenH264Target(
  platform: 'linux64',
  cdnStem: 'libopenh264',
  cdnSuffix: '7.so',
  payloadName: 'libopenh264.so.7',
  sha256: 'd828a944d4d2bb64195ada89cf2cde9bc41733b1547d0788ef49fb8cb231b76f',
);

const _openH264TargetLinuxArm64 = _OpenH264Target(
  platform: 'linux-arm64',
  cdnStem: 'libopenh264',
  cdnSuffix: '7.so',
  payloadName: 'libopenh264.so.7',
  sha256: 'aab3312e2e7e49a8e24793bf1b9e752e658edd98a7542ae8e9d16fbede0c7327',
);

const _openH264TargetWin64 = _OpenH264Target(
  platform: 'win64',
  cdnStem: 'openh264',
  cdnSuffix: 'dll',
  payloadName: 'openh264.dll',
  sha256: 'b3e3d5a65616fe26ee8659a22f5b52cbaea8025031e59bfd3f1cbe489e832e69',
);

const _openH264TargetWinArm64 = _OpenH264Target(
  platform: 'win-arm64',
  cdnStem: 'openh264',
  cdnSuffix: 'dll',
  payloadName: 'openh264.dll',
  sha256: 'f5976bff9e6de84f6253c9bff0f7c70ccde446b3b20cf7b7206f7a12c35b460f',
);

_OpenH264Target _resolveOpenH264Target(OS os, Architecture arch) {
  if (os == OS.linux) {
    return switch (arch) {
      Architecture.x64 => _openH264TargetLinuxX64,
      Architecture.arm64 => _openH264TargetLinuxArm64,
      _ => throw UnsupportedError(
          'OpenH264 prebuilt: unsupported Linux arch $arch'),
    };
  }
  if (os == OS.windows) {
    return switch (arch) {
      Architecture.x64 => _openH264TargetWin64,
      Architecture.arm64 => _openH264TargetWinArm64,
      _ => throw UnsupportedError(
          'OpenH264 prebuilt: unsupported Windows arch $arch'),
    };
  }
  throw UnsupportedError('OpenH264 prebuilt: unsupported OS $os');
}

/// Upstream LICENSE text for OpenH264, pinned by SHA-256 so we catch any
/// drift in the Cisco BSD-2 wording. The binary releases at 2.5.1 etc
/// don't get their own source tags (Cisco only tags major minors); the
/// closest source tag is v2.5.0 and the LICENSE file has been unchanged
/// since 2013 so cross-version drift is effectively impossible. Kept as
/// a separate constant from `_openH264Version` so future maintainers
/// see the deliberate divergence.
const String _openH264LicenseTag = 'v2.5.0';
const String _openH264LicenseUrl =
    'https://raw.githubusercontent.com/cisco/openh264/$_openH264LicenseTag/LICENSE';
const String _openH264LicenseSha =
    'dd5c1c9668512530fa5a96e4c29ac4033d70a7eeb0eed7a42fddb6dd794ebdbb';

Future<void> _bundleOpenH264(
    BuildInput input, BuildOutputBuilder output) async {
  final target = _resolveOpenH264Target(
      input.config.code.targetOS, input.config.code.targetArchitecture);

  final shared = input.outputDirectoryShared;
  final cacheDir = Directory.fromUri(
      shared.resolve('openh264-$_openH264Version-${target.platform}/'));
  final payloadFile =
      File.fromUri(cacheDir.uri.resolve(target.payloadName));

  if (!payloadFile.existsSync() ||
      await _sha256Hex(payloadFile) != target.sha256) {
    await cacheDir.create(recursive: true);
    final bz2File =
        File.fromUri(cacheDir.uri.resolve('${target.payloadName}.bz2'));
    await _downloadFile(target.cdnUrl, bz2File);
    // BZip2Decoder is pure Dart (package:archive), so no `bunzip2` /
    // 7-Zip system dependency — works identically on Linux, macOS and
    // Windows runners.
    final decoded = BZip2Decoder().decodeBytes(await bz2File.readAsBytes());
    await payloadFile.writeAsBytes(decoded);
    await bz2File.delete();
    final actualSha = await _sha256Hex(payloadFile);
    if (actualSha != target.sha256) {
      throw StateError(
          'OpenH264 prebuilt SHA-256 mismatch for ${target.platform}:\n'
          '  expected: ${target.sha256}\n'
          '  actual:   $actualSha\n'
          'Either Cisco re-published the binary (verify and update '
          'the matching _openH264Target* constant), or the download was '
          'corrupted.');
    }
    // Emit OpenH264's BSD-2 LICENSE alongside the binary so any consumer
    // inspecting the cache directory finds the governing license text.
    // The body comes verbatim from upstream (SHA-pinned); the header
    // is a neutral pointer back to https://www.openh264.org/.
    final licenseFile = File.fromUri(cacheDir.uri.resolve('LICENSE'));
    await _downloadFile(_openH264LicenseUrl, licenseFile);
    final licenseSha = await _sha256Hex(licenseFile);
    if (licenseSha != _openH264LicenseSha) {
      throw StateError(
          'OpenH264 LICENSE SHA-256 mismatch:\n'
          '  expected: $_openH264LicenseSha\n'
          '  actual:   $licenseSha\n'
          'Upstream may have changed the BSD-2 wording — verify and '
          'update _openH264LicenseSha.');
    }
    final licenseBody = await licenseFile.readAsString();
    await File.fromUri(cacheDir.uri.resolve('NOTICE.txt'))
        .writeAsString('$_openH264NoticeHeader\n$licenseBody');
  }

  output.assets.code.add(CodeAsset(
    package: 'webdartc',
    name: 'codec/h264/_openh264.dart',
    linkMode: DynamicLoadingBundled(),
    file: payloadFile.uri,
  ));
}

const String _openH264NoticeHeader = '''
OpenH264 — Cisco prebuilt binary
================================

The OpenH264 shared library in this directory was downloaded from
https://ciscobinary.openh264.org/. See https://www.openh264.org/ for
the upstream project's distribution terms.

OpenH264 is licensed under BSD 2-Clause (verbatim from
$_openH264LicenseUrl):
''';

Future<void> _downloadFile(String url, File dest) async {
  final client = HttpClient();
  try {
    final req = await client.getUrl(Uri.parse(url));
    final resp = await req.close();
    if (resp.statusCode != 200) {
      throw StateError('GET $url returned HTTP ${resp.statusCode}');
    }
    final sink = dest.openWrite();
    await resp.pipe(sink);
  } finally {
    client.close(force: true);
  }
}

// ── libvpx on Windows ──────────────────────────────────────────────────
//
// Default path downloads webdartc-libvpx-prebuilt-<ver>-r<rev>-<plat>.zip
// from the matching `vpx-prebuilt-*` GitHub release on this repo and
// hands the two DLLs to the asset registry. The release contents are
// produced by `.github/workflows/build-libvpx-prebuilt.yaml`, which in
// turn drives `tool/build_libvpx_wrappers.dart`.
//
// Bumping the libvpx pin:
//   1. Edit `tool/libvpx_vcpkg/vcpkg.json` (libvpx version and
//      `builtin-baseline`).
//   2. Bump `WRAPPER_REVISION` in the workflow if wrapper sources also
//      changed since the prior release.
//   3. Land that change, then tag `vpx-prebuilt-v<ver>-r<rev>` and let
//      the workflow publish the zip assets.
//   4. Read the published zip SHA-256 off the release (or
//      `gh release view <tag> --json assets`) and update the matching
//      `_libvpxPrebuiltWin*` constant below + the version constants.

const String _libvpxVersion = '1.16.0';
const String _libvpxWrapperRev = 'r1';
const String _libvpxReleaseTag =
    'vpx-prebuilt-v$_libvpxVersion-$_libvpxWrapperRev';

class _LibvpxPrebuilt {
  /// `win-x64` or `win-arm64`. Used in the cache directory, zip filename
  /// and the published GitHub asset name.
  final String platform;

  /// SHA-256 of the published zip as a whole. The zip's individual
  /// payloads (`webdartc_vp{8,9}.dll`, `LICENSE`, `NOTICE.txt`) inherit
  /// their integrity from the zip's SHA.
  final String zipSha256;

  const _LibvpxPrebuilt({required this.platform, required this.zipSha256});

  String get zipName =>
      'webdartc-libvpx-prebuilt-v$_libvpxVersion-$_libvpxWrapperRev-$platform.zip';

  String get downloadUrl =>
      'https://github.com/nus/webdartc/releases/download/$_libvpxReleaseTag/$zipName';
}

const _libvpxPrebuiltWinX64 = _LibvpxPrebuilt(
  platform: 'win-x64',
  zipSha256: '26fb097ae4786ef7d354df84263a132eb5c1e61b394da5a812d0775e0068112d',
);

const _libvpxPrebuiltWinArm64 = _LibvpxPrebuilt(
  platform: 'win-arm64',
  zipSha256: '487d5c8c5d850135c04f5cbbcc931ece33a09aec6239846ca2158806267015db',
);

_LibvpxPrebuilt _resolveLibvpxPrebuilt(Architecture arch) => switch (arch) {
      Architecture.x64 => _libvpxPrebuiltWinX64,
      Architecture.arm64 => _libvpxPrebuiltWinArm64,
      _ => throw UnsupportedError(
          'libvpx prebuilt: unsupported Windows arch $arch'),
    };

Future<void> _bundleLibvpxPrebuilt(
    BuildInput input, BuildOutputBuilder output) async {
  final prebuilt =
      _resolveLibvpxPrebuilt(input.config.code.targetArchitecture);

  final cacheDir = Directory.fromUri(input.outputDirectoryShared.resolve(
      'libvpx-prebuilt-$_libvpxReleaseTag-${prebuilt.platform}/'));
  final vp8 = File.fromUri(cacheDir.uri.resolve('webdartc_vp8.dll'));
  final vp9 = File.fromUri(cacheDir.uri.resolve('webdartc_vp9.dll'));
  // Marker so we can re-verify the cache hit against the expected SHA
  // without keeping the original zip around.
  final marker = File.fromUri(cacheDir.uri.resolve('zip.sha256'));

  final cached = vp8.existsSync() &&
      vp9.existsSync() &&
      marker.existsSync() &&
      (await marker.readAsString()).trim() == prebuilt.zipSha256;

  if (!cached) {
    await cacheDir.create(recursive: true);
    final zipFile = File.fromUri(cacheDir.uri.resolve(prebuilt.zipName));
    await _downloadFile(prebuilt.downloadUrl, zipFile);
    final actualSha = await _sha256Hex(zipFile);
    if (actualSha != prebuilt.zipSha256) {
      throw StateError(
          'libvpx prebuilt SHA-256 mismatch for ${prebuilt.platform}:\n'
          '  expected: ${prebuilt.zipSha256}\n'
          '  actual:   $actualSha\n'
          'Either the release asset was re-uploaded (verify and update '
          'the matching _libvpxPrebuiltWin* constant) or the download '
          'was corrupted.');
    }
    final archive = ZipDecoder().decodeBytes(await zipFile.readAsBytes());
    for (final entry in archive.files) {
      if (!entry.isFile) continue;
      final out = File.fromUri(cacheDir.uri.resolve(entry.name));
      await out.create(recursive: true);
      await out.writeAsBytes(entry.content as List<int>);
    }
    await zipFile.delete();
    await marker.writeAsString(prebuilt.zipSha256);
  }

  _registerLibvpxWrappers(output, cacheDir.uri);
}

Future<void> _buildLibvpxFromSource(
    BuildInput input, BuildOutputBuilder output) async {
  final outDir = await _windowsWrapperSourceBuild(
    input: input,
    label: 'libvpx',
    scriptRelPath: 'tool/build_libvpx_wrappers.dart',
    manifestRelPath: 'tool/libvpx_vcpkg',
  );
  _registerLibvpxWrappers(output, outDir);
}

/// Drives one of the `tool/build_lib*_wrappers.dart` scripts under an
/// MSVC environment. Shared by `_buildLibvpxFromSource` and
/// `_buildLibopusFromSource`; returns the directory URI containing the
/// resulting wrapper DLL(s) for the caller to register as code assets.
Future<Uri> _windowsWrapperSourceBuild({
  required BuildInput input,
  required String label,
  required String scriptRelPath,
  required String manifestRelPath,
}) async {
  final arch = input.config.code.targetArchitecture;
  final triplet = switch (arch) {
    Architecture.x64 => 'x64-windows-static',
    Architecture.arm64 => 'arm64-windows-static',
    _ => throw UnsupportedError(
        '$label source build: unsupported Windows arch $arch'),
  };

  final outDir = Directory.fromUri(input.outputDirectoryShared
      .resolve('$label-source-build-$triplet/'));
  await outDir.create(recursive: true);

  final pkg = input.packageRoot;
  final scriptPath = pkg.resolve(scriptRelPath).toFilePath();
  final manifestDir = pkg.resolve(manifestRelPath).toFilePath();
  final srcDir = pkg.resolve('src').toFilePath();
  // Directory.path keeps the trailing `\`; trim it so the closing `"`
  // in `--out-dir="$outPath"` isn't escaped to a literal quote.
  final outPath = outDir.path.endsWith(r'\')
      ? outDir.path.substring(0, outDir.path.length - 1)
      : outDir.path;

  // hooks_runner runs the build hook with a scrubbed environment, so
  // MSVC's INCLUDE / LIB / PATH from a Developer Command Prompt is gone
  // by the time we reach here. Source vcvarsall.bat into a wrapper batch
  // before invoking `dart <script>`.
  //
  // `dart <script>` (no `run`) executes the script directly — `dart run`
  // would recursively re-enter `package:hooks_runner` and deadlock on
  // the same `.lock` file this hook is already holding.
  final vcvarsall =
      r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat';
  final vcvarsArch = _vcvarsArchArg(arch);
  // Place the launcher .bat outside outDir so it survives the wrapper
  // script's post-run cleanup of non-DLL files — otherwise cmd loses
  // the file mid-execution and reports "batch file not found".
  final batPath = input.outputDirectory
      .resolve('$label-source-build-$triplet.bat')
      .toFilePath();
  File(batPath).writeAsStringSync(
    '@echo off\r\n'
    'call "$vcvarsall" $vcvarsArch\r\n'
    'if errorlevel 1 exit /b 1\r\n'
    '"${Platform.resolvedExecutable}" "$scriptPath"'
    ' --triplet=$triplet'
    ' --manifest-dir="$manifestDir"'
    ' --src-dir="$srcDir"'
    ' --out-dir="$outPath"\r\n',
  );
  await _runChecked('cmd', ['/c', batPath],
      desc: '$label wrapper source build ($triplet)');

  return outDir.uri;
}

/// Translates an asset target arch into the `vcvarsall.bat` first
/// argument, picking the cross-compile combination based on the host
/// arch (`PROCESSOR_ARCHITECTURE`).
String _vcvarsArchArg(Architecture target) {
  final host =
      (Platform.environment['PROCESSOR_ARCHITECTURE'] ?? 'AMD64').toUpperCase();
  final hostTok = host == 'ARM64' ? 'arm64' : 'amd64';
  final targetTok = switch (target) {
    Architecture.x64 => 'amd64',
    Architecture.arm64 => 'arm64',
    _ => throw UnsupportedError('vcvarsall: unsupported target $target'),
  };
  return hostTok == targetTok ? targetTok : '${hostTok}_$targetTok';
}

Future<String> _sha256Hex(File f) async {
  if (!f.existsSync()) return '';
  final digest = await sha256.bind(f.openRead()).first;
  return digest.toString();
}

// ── libopus on Windows ─────────────────────────────────────────────────
//
// Same shape as the libvpx Windows section above: the default path
// downloads `webdartc-libopus-prebuilt-v<ver>-r<rev>-<plat>.zip` from the
// matching `opus-prebuilt-*` GitHub release on this repo, produced by
// `.github/workflows/build-libopus-prebuilt.yaml` (which drives
// `tool/build_libopus_wrappers.dart`). The `libopus_source_build: true`
// user-define switches to a local source build of the same wrapper.
//
// Bumping the libopus pin:
//   1. Edit `tool/libopus_vcpkg/vcpkg.json` (libopus version and
//      `builtin-baseline`).
//   2. Bump `WRAPPER_REVISION` in the workflow if wrapper sources also
//      changed since the prior release.
//   3. Land that change, then tag `opus-prebuilt-v<ver>-r<rev>` and let
//      the workflow publish the zip assets.
//   4. Read the published zip SHA-256 off the release (or
//      `gh release view <tag> --json assets`) and update the matching
//      `_libopusPrebuiltWin*` constant below + the version constants.

const String _libopusVersion = '1.5.2';
const String _libopusWrapperRev = 'r1';
const String _libopusReleaseTag =
    'opus-prebuilt-v$_libopusVersion-$_libopusWrapperRev';

class _LibopusPrebuilt {
  /// `win-x64` or `win-arm64`. Used in the cache directory, zip filename
  /// and the published GitHub asset name.
  final String platform;

  /// SHA-256 of the published zip as a whole. The zip's individual
  /// payloads (`webdartc_opus.dll`, `LICENSE`, `NOTICE.txt`) inherit
  /// their integrity from the zip's SHA.
  final String zipSha256;

  const _LibopusPrebuilt({required this.platform, required this.zipSha256});

  String get zipName =>
      'webdartc-libopus-prebuilt-v$_libopusVersion-$_libopusWrapperRev-$platform.zip';

  String get downloadUrl =>
      'https://github.com/nus/webdartc/releases/download/$_libopusReleaseTag/$zipName';
}

const _libopusPrebuiltWinX64 = _LibopusPrebuilt(
  platform: 'win-x64',
  zipSha256: 'fcbc655462b793f56e79255fb4a7ca72af9348cc150a6d1c2e630f3777853c93',
);

const _libopusPrebuiltWinArm64 = _LibopusPrebuilt(
  platform: 'win-arm64',
  zipSha256: '60a0c57ab4fd98e20abaa4ef1f03716fc073e4d90073bdcb768994618c72a483',
);

_LibopusPrebuilt _resolveLibopusPrebuilt(Architecture arch) => switch (arch) {
      Architecture.x64 => _libopusPrebuiltWinX64,
      Architecture.arm64 => _libopusPrebuiltWinArm64,
      _ => throw UnsupportedError(
          'libopus prebuilt: unsupported Windows arch $arch'),
    };

Future<void> _bundleLibopusPrebuilt(
    BuildInput input, BuildOutputBuilder output) async {
  final prebuilt =
      _resolveLibopusPrebuilt(input.config.code.targetArchitecture);

  if (prebuilt.zipSha256.isEmpty) {
    throw StateError(
        'libopus prebuilt for ${prebuilt.platform} has no published zip yet '
        '— tag `$_libopusReleaseTag` first to trigger '
        'build-libopus-prebuilt.yaml, then read the asset SHA-256 and '
        'update the matching _libopusPrebuiltWin* constant. To build '
        'locally instead, set '
        '`hooks.user_defines.webdartc.libopus_source_build: true` '
        'in pubspec.yaml (requires vcpkg + MSVC).');
  }

  final cacheDir = Directory.fromUri(input.outputDirectoryShared.resolve(
      'libopus-prebuilt-$_libopusReleaseTag-${prebuilt.platform}/'));
  final dll = File.fromUri(cacheDir.uri.resolve('webdartc_opus.dll'));
  // Marker so we can re-verify the cache hit against the expected SHA
  // without keeping the original zip around.
  final marker = File.fromUri(cacheDir.uri.resolve('zip.sha256'));

  final cached = dll.existsSync() &&
      marker.existsSync() &&
      (await marker.readAsString()).trim() == prebuilt.zipSha256;

  if (!cached) {
    await cacheDir.create(recursive: true);
    final zipFile = File.fromUri(cacheDir.uri.resolve(prebuilt.zipName));
    await _downloadFile(prebuilt.downloadUrl, zipFile);
    final actualSha = await _sha256Hex(zipFile);
    if (actualSha != prebuilt.zipSha256) {
      throw StateError(
          'libopus prebuilt SHA-256 mismatch for ${prebuilt.platform}:\n'
          '  expected: ${prebuilt.zipSha256}\n'
          '  actual:   $actualSha\n'
          'Either the release asset was re-uploaded (verify and update '
          'the matching _libopusPrebuiltWin* constant) or the download '
          'was corrupted.');
    }
    final archive = ZipDecoder().decodeBytes(await zipFile.readAsBytes());
    for (final entry in archive.files) {
      if (!entry.isFile) continue;
      final out = File.fromUri(cacheDir.uri.resolve(entry.name));
      await out.create(recursive: true);
      await out.writeAsBytes(entry.content as List<int>);
    }
    await zipFile.delete();
    await marker.writeAsString(prebuilt.zipSha256);
  }

  _registerLibopusWrapper(output, cacheDir.uri);
}

Future<void> _buildLibopusFromSource(
    BuildInput input, BuildOutputBuilder output) async {
  final outDir = await _windowsWrapperSourceBuild(
    input: input,
    label: 'libopus',
    scriptRelPath: 'tool/build_libopus_wrappers.dart',
    manifestRelPath: 'tool/libopus_vcpkg',
  );
  _registerLibopusWrapper(output, outDir);
}
