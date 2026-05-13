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
      if (targetOS == OS.macOS || targetOS == OS.iOS)
        _buildVtCallback(input, output),
      if (targetOS == OS.macOS || targetOS == OS.linux) ...[
        _buildOpusCodecs(input, output),
        _buildVp8Codec(input, output),
        _buildVp9Codec(input, output),
      ],
      if (targetOS == OS.linux || targetOS == OS.windows)
        _bundleOpenH264(input, output),
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

Future<String> _sha256Hex(File f) async {
  if (!f.existsSync()) return '';
  final digest = await sha256.bind(f.openRead()).first;
  return digest.toString();
}
