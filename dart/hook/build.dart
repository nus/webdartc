// Build hook for webdartc native code assets.
//
// Apple platforms (macOS / iOS): compile the VideoToolbox callback shim.
// Every non-Apple-H.264 codec is source-built and linked into a dedicated
// wrapper shared library:
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
// Codec source per platform:
//   - macOS / Windows: vcpkg ports (pinned by `tool/lib*_vcpkg/vcpkg.json`).
//     vcpkg is auto-cloned + bootstrapped by [_vcpkgExe] if not already on
//     VCPKG_ROOT / PATH. Windows additionally needs MSVC (vcvarsall.bat),
//     which `flutter build windows` already requires.
//   - Linux / Android: the bundled `third_party/{opus,libvpx}` submodules,
//     built with cmake / configure+make.
//
// Linux + Windows also bundle Cisco's prebuilt OpenH264 dylib/dll
// (downloaded by [_bundleOpenH264]). macOS uses VideoToolbox so OpenH264
// isn't shipped there.
//
// Linux + Android crypto links BoringSSL (vcpkg) into webdartc_crypto;
// macOS / Windows use the platform-native crypto backends instead.

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
      if (targetOS == OS.macOS ||
          targetOS == OS.linux ||
          targetOS == OS.android) ...[
        _buildOpusCodecs(input, output),
        _buildVp8Codec(input, output),
        _buildVp9Codec(input, output),
      ],
      if (targetOS == OS.linux || targetOS == OS.windows)
        _bundleOpenH264(input, output),
      if (targetOS == OS.windows) ...[
        _buildLibvpxFromSource(input, output),
        _buildLibopusFromSource(input, output),
      ],
      // Linux + Android crypto: BoringSSL (built via vcpkg) statically linked
      // into the webdartc_crypto wrapper. macOS=Security.framework /
      // Windows=CNG provide crypto natively, so no wrapper there.
      if (targetOS == OS.linux || targetOS == OS.android)
        _buildBoringSslCrypto(input, output),
    ]);
  });
}

const _libvpxCodecs = ['vp8', 'vp9'];

/// Emits `CodeAsset`s for each `webdartc_vp{8,9}.dll` sitting under [dllDir]
/// (the Windows source-build output directory).
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

/// Emits the `CodeAsset` for `webdartc_opus.dll` sitting under [dllDir]
/// (the Windows source-build output directory).
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
  final targetOS = input.config.code.targetOS;
  // macOS sources libopus via vcpkg; Linux / Android build the bundled
  // submodule with cmake. Both produce a static `libopus.a` + `include/opus/`
  // that the wrapper below links the same way.
  final (opusInstall, libopusA) = targetOS == OS.macOS
      ? await _vcpkgBuildOpus(input)
      : await _cmakeBuildOpus(input);
  final includeDir = opusInstall.resolve('include/opus/').toFilePath();

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
      // Android keeps libm separate from libc and the NDK linker won't
      // auto-add it; libopus pulls in log/exp/pow.
      if (targetOS == OS.android) '-lm',
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
/// assembled by nasm, which doesn't emit visibility metadata at all.
/// macOS `ld64` rescans archives and respects per-symbol visibility,
/// so neither flag is needed there.
List<String> _linkArchive(OS targetOS, String archivePath) {
  // macOS: vcpkg builds libvpx/libopus with default symbol visibility (unlike
  // our submodule builds, which pass `-fvisibility=hidden`), so ld64 would
  // otherwise re-export the archive's `vpx_*` / `opus_*` symbols from the
  // wrapper dylib. Whitelist only `_webdartc_*` exports so the wrapper stays
  // isolated regardless of how the archive was built. (Codec wrappers are the
  // only macOS users of _linkArchive; native crypto doesn't go through here.)
  if (targetOS == OS.macOS) {
    return [archivePath, '-Wl,-exported_symbol,_webdartc_*'];
  }
  // Android links with lld, which (like GNU ld) is single-pass and
  // re-exports whole-archive members, so it needs the same treatment as
  // Linux.
  if (targetOS != OS.linux && targetOS != OS.android) return [archivePath];
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
  final targetOS = input.config.code.targetOS;
  // On Android the per-ABI name (arm64-v8a / x86_64 / …) doubles as both the
  // cache-directory key and the cmake ANDROID_ABI value.
  final arch = targetOS == OS.android
      ? _androidAbi(input.config.code.targetArchitecture)
      : switch (input.config.code.targetArchitecture) {
          Architecture.arm64 => 'arm64',
          Architecture.x64 => 'x86_64',
          final a => throw UnsupportedError('libopus build: unsupported arch $a'),
        };
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
    if (targetOS == OS.android) ...[
      '-DCMAKE_TOOLCHAIN_FILE='
          '${_androidNdk(input).ndkRoot.resolve('build/cmake/android.toolchain.cmake').toFilePath()}',
      '-DANDROID_ABI=$arch',
      '-DANDROID_PLATFORM=android-${input.config.code.android.targetNdkApi}',
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
  final targetOS = input.config.code.targetOS;
  // macOS sources libvpx via vcpkg; Linux / Android build the bundled
  // submodule with configure+make. Both produce a static `libvpx.a` +
  // `include/vpx/` that the wrapper below links the same way.
  final (vpxInstall, libvpxA) = targetOS == OS.macOS
      ? await _vcpkgBuildLibvpx(input)
      : await _configureMakeLibvpx(input);
  final includeDir = vpxInstall.resolve('include/').toFilePath();
  final builder = CBuilder.library(
    name: name,
    assetName: assetName,
    sources: [source],
    includes: [includeDir],
    flags: [
      '-fvisibility=hidden',
      ..._linkArchive(targetOS, libvpxA),
      // Android keeps libm separate from libc; libvpx's rate control pulls in
      // log10/pow and the NDK linker won't auto-add it.
      if (targetOS == OS.android) '-lm',
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
  // Android: libvpx's `*-android-gcc` standalone build reads the toolchain
  // from CC/CXX/AR/AS/LD/STRIP/NM/RANLIB. The NDK ships per-API clang
  // wrappers (`<triple><api>-clang`) that bake in --target and --sysroot, so
  // no extra cflags beyond visibility are needed.
  final env = targetOS == OS.android ? _androidLibvpxEnv(input, arch) : null;
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
  ], desc: 'libvpx configure', workingDirectory: buildDir.path, environment: env);
  await _runChecked('make', [
    '-C', buildDir.path,
    '-j${Platform.numberOfProcessors}',
    'install',
  ], desc: 'libvpx make install', environment: env);
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
  if (targetOS == OS.android) {
    // libvpx's `*-android-gcc` targets are "standalone NDK toolchain" builds:
    // the actual cross-compiler comes from the CC/AS/AR env vars set in
    // [_configureMakeLibvpxOnce]; the tuple only selects ISA features.
    return switch (arch) {
      Architecture.arm64 => 'arm64-android-gcc',
      Architecture.arm => 'armv7-android-gcc',
      Architecture.x64 => 'x86_64-android-gcc',
      Architecture.ia32 => 'x86-android-gcc',
      _ => throw UnsupportedError('libvpx Android build: unsupported arch $arch'),
    };
  }
  throw UnsupportedError('libvpx build: unsupported OS $targetOS');
}

Future<void> _runChecked(String exe, List<String> args,
    {required String desc,
    String? workingDirectory,
    Map<String, String>? environment}) async {
  final r = await Process.run(exe, args,
      workingDirectory: workingDirectory, environment: environment);
  if (r.exitCode != 0) {
    throw StateError('$desc failed:\n${r.stdout}\n${r.stderr}');
  }
}

// ── Android NDK helpers ────────────────────────────────────────────────────
//
// The codec libraries (libopus via CMake, libvpx via configure) are built by
// invoking their own build systems, so unlike the `CBuilder` path they need
// the NDK located explicitly. The NDK clang reported in the hook's
// `cCompiler` config lives at
// `<ndk>/toolchains/llvm/prebuilt/<host>/bin/clang`; both the NDK root and
// the toolchain `bin/` directory are derived from it, with a fallback that
// scans the standard SDK install locations.

/// Android ABI name (also the libopus cmake `ANDROID_ABI` and per-ABI cache
/// key).
String _androidAbi(Architecture arch) => switch (arch) {
      Architecture.arm64 => 'arm64-v8a',
      Architecture.arm => 'armeabi-v7a',
      Architecture.x64 => 'x86_64',
      Architecture.ia32 => 'x86',
      _ => throw UnsupportedError('Android: unsupported arch $arch'),
    };

/// NDK clang wrapper triple prefix; the per-API wrapper is
/// `<triple><api>-clang`.
String _androidClangTriple(Architecture arch) => switch (arch) {
      Architecture.arm64 => 'aarch64-linux-android',
      Architecture.arm => 'armv7a-linux-androideabi',
      Architecture.x64 => 'x86_64-linux-android',
      Architecture.ia32 => 'i686-linux-android',
      _ => throw UnsupportedError('Android: unsupported arch $arch'),
    };

/// Resolved NDK root + toolchain `bin/` directory.
({Uri ndkRoot, Uri binDir}) _androidNdk(BuildInput input) {
  final cc = input.config.code.cCompiler?.compiler;
  if (cc != null) {
    // <ndk>/toolchains/llvm/prebuilt/<host>/bin/clang → root is 5 levels up,
    // bin/ is the compiler's own directory.
    return (ndkRoot: cc.resolve('../../../../../'), binDir: cc.resolve('./'));
  }
  final root = _findAndroidNdk();
  if (root == null) {
    throw StateError(
        'Android NDK not found: no cCompiler in the hook config and none of '
        'the standard SDK locations (ANDROID_HOME/ndk, '
        '~/Library/Android/sdk/ndk, ~/Android/Sdk/ndk) contain an NDK. Set '
        'ANDROID_NDK_HOME.');
  }
  final prebuilt = Directory.fromUri(root.resolve('toolchains/llvm/prebuilt/'));
  final host = prebuilt.listSync().whereType<Directory>().first;
  return (ndkRoot: root, binDir: Directory(host.path).uri.resolve('bin/'));
}

/// Scans the conventional NDK install locations, picking the newest version.
Uri? _findAndroidNdk() {
  final env = Platform.environment;
  final direct = env['ANDROID_NDK_HOME'] ?? env['ANDROID_NDK_ROOT'];
  if (direct != null && Directory(direct).existsSync()) {
    return Directory(direct).uri;
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
    if (versions.isNotEmpty) return Directory(versions.last.path).uri;
  }
  return null;
}

/// CC/CXX/AR/AS/LD/STRIP/NM/RANLIB env for libvpx's standalone NDK build.
Map<String, String> _androidLibvpxEnv(BuildInput input, Architecture arch) {
  final ndk = _androidNdk(input);
  final api = input.config.code.android.targetNdkApi;
  final triple = _androidClangTriple(arch);
  String bin(String exe) => ndk.binDir.resolve(exe).toFilePath();
  final cc = bin('$triple$api-clang');
  return {
    'CC': cc,
    'CXX': bin('$triple$api-clang++'),
    'LD': cc,
    'AS': cc, // clang's integrated assembler
    'AR': bin('llvm-ar'),
    'STRIP': bin('llvm-strip'),
    'NM': bin('llvm-nm'),
    'RANLIB': bin('llvm-ranlib'),
  };
}

// ── BoringSSL crypto (Linux + Android) ──────────────────────────────────────
//
// vcpkg source-builds BoringSSL's static `libcrypto.a` per triplet; the
// `webdartc_crypto` wrapper statically links it and exports only the `wd_*`
// passthroughs (src/webdartc_crypto.{h,c}), which `lib/crypto/openssl.dart`
// binds via `@Native`. Same hide-the-static-lib shape as the libvpx/libopus
// wrappers. vcpkg is located via `VCPKG_ROOT` / PATH, else cloned + bootstrapped
// into the shared cache (so end users need no manual vcpkg setup). Requires a C
// toolchain + cmake + pkg-config on the build machine (vcpkg builds BoringSSL).

Future<void> _buildBoringSslCrypto(
    BuildInput input, BuildOutputBuilder output) async {
  final (includeDir, libcryptoA) = await _buildBoringSslArchive(input);
  final targetOS = input.config.code.targetOS;
  final builder = CBuilder.library(
    name: 'webdartc_crypto',
    assetName: 'crypto/webdartc_crypto.dart',
    sources: ['src/webdartc_crypto.c'],
    includes: [includeDir],
    flags: [
      '-fvisibility=hidden',
      ..._linkArchive(targetOS, libcryptoA),
      // BoringSSL's libcrypto uses pthreads; Android's libc bundles them.
      if (targetOS == OS.linux) '-lpthread',
    ],
  );
  await builder.run(input: input, output: output);
}

/// vcpkg-builds BoringSSL for the target triplet, returning (includeDir,
/// libcrypto.a path). Thin adapter over [_vcpkgInstall] — Android passes its
/// NDK root through to the port build.
Future<(String, String)> _buildBoringSslArchive(BuildInput input) async {
  final triplet = _boringSslTriplet(
      input.config.code.targetOS, input.config.code.targetArchitecture);
  final environment = <String, String>{};
  if (input.config.code.targetOS == OS.android) {
    environment['ANDROID_NDK_HOME'] = _androidNdk(input).ndkRoot.toFilePath();
  }
  final (tripletRoot, libcryptoA) = await _vcpkgInstall(
    input: input,
    triplet: triplet,
    manifestRelPath: 'tool/boringssl_vcpkg',
    cacheSubdir: 'boringssl-vcpkg',
    archiveRelPath: 'lib/libcrypto.a',
    environment: environment.isEmpty ? null : environment,
  );
  return (Directory.fromUri(tripletRoot.resolve('include/')).path, libcryptoA);
}

String _boringSslTriplet(OS targetOS, Architecture arch) {
  if (targetOS == OS.linux) {
    return switch (arch) {
      Architecture.arm64 => 'arm64-linux',
      Architecture.x64 => 'x64-linux',
      _ => throw UnsupportedError('BoringSSL Linux: unsupported arch $arch'),
    };
  }
  if (targetOS == OS.android) {
    return switch (arch) {
      Architecture.arm64 => 'arm64-android',
      Architecture.arm => 'arm-neon-android',
      Architecture.x64 => 'x64-android',
      Architecture.ia32 => 'x86-android',
      _ => throw UnsupportedError('BoringSSL Android: unsupported arch $arch'),
    };
  }
  throw UnsupportedError('BoringSSL build: unsupported OS $targetOS');
}

// ── macOS codec source build via vcpkg ──────────────────────────────────
//
// On macOS the libvpx / libopus static archives come from vcpkg's ports
// (pinned by `tool/lib*_vcpkg/vcpkg.json`) instead of the bundled
// submodules, mirroring the BoringSSL crypto path above. The resulting
// `.a` + headers are linked into the same `webdartc_vp{8,9}` / `webdartc_codecs`
// wrappers by [_buildLibvpxWrapper] / [_buildOpusCodecs]. Linux / Android
// keep building the submodules with configure+make / cmake.

/// vcpkg-builds libvpx for the macOS target, returning the install prefix
/// URI (`include/`, `lib/`) plus the resolved `libvpx.a` path.
Future<(Uri, String)> _vcpkgBuildLibvpx(BuildInput input) => _vcpkgInstall(
      input: input,
      triplet: _osxTriplet(input.config.code.targetArchitecture),
      manifestRelPath: 'tool/libvpx_vcpkg',
      cacheSubdir: 'libvpx-vcpkg',
      archiveRelPath: 'lib/libvpx.a',
      overlayTriplets: true,
    );

/// vcpkg-builds libopus for the macOS target, returning the install prefix
/// URI (`include/opus/`, `lib/`) plus the resolved `libopus.a` path.
Future<(Uri, String)> _vcpkgBuildOpus(BuildInput input) => _vcpkgInstall(
      input: input,
      triplet: _osxTriplet(input.config.code.targetArchitecture),
      manifestRelPath: 'tool/libopus_vcpkg',
      cacheSubdir: 'opus-vcpkg',
      archiveRelPath: 'lib/libopus.a',
      overlayTriplets: true,
    );

String _osxTriplet(Architecture arch) => switch (arch) {
      Architecture.arm64 => 'arm64-osx',
      Architecture.x64 => 'x64-osx',
      _ => throw UnsupportedError('macOS vcpkg build: unsupported arch $arch'),
    };

/// In-process memoisation keyed on `<cacheSubdir>/<triplet>`. Concurrent
/// callers for the same port (e.g. the VP8 + VP9 wrappers both needing libvpx)
/// share one `vcpkg install` instead of racing two against the same root.
final Map<String, Future<(Uri, String)>> _vcpkgInstalls = {};

/// The single `vcpkg install` primitive shared by every vcpkg consumer
/// (BoringSSL crypto, libvpx, libopus). Installs the port whose manifest lives
/// at [manifestRelPath] for [triplet] and returns the per-triplet install
/// prefix URI (`include/`, `lib/`) plus the resolved static archive path.
/// Cached under [BuildInput.outputDirectoryShared]/[cacheSubdir]/, re-validated
/// by the archive's existence.
///
/// [overlayTriplets] adds `--overlay-triplets=tool/vcpkg_triplets/`, whose
/// `*-osx` triplets pin VCPKG_OSX_DEPLOYMENT_TARGET so the vendored objects'
/// Mach-O minimum stays no newer than the wrapper dylib's. [environment] is
/// forwarded to the install (Android passes `ANDROID_NDK_HOME`).
Future<(Uri, String)> _vcpkgInstall({
  required BuildInput input,
  required String triplet,
  required String manifestRelPath,
  required String cacheSubdir,
  required String archiveRelPath,
  bool overlayTriplets = false,
  Map<String, String>? environment,
}) =>
    _vcpkgInstalls['$cacheSubdir/$triplet'] ??= _vcpkgInstallOnce(
      input: input,
      triplet: triplet,
      manifestRelPath: manifestRelPath,
      cacheSubdir: cacheSubdir,
      archiveRelPath: archiveRelPath,
      overlayTriplets: overlayTriplets,
      environment: environment,
    );

Future<(Uri, String)> _vcpkgInstallOnce({
  required BuildInput input,
  required String triplet,
  required String manifestRelPath,
  required String cacheSubdir,
  required String archiveRelPath,
  required bool overlayTriplets,
  required Map<String, String>? environment,
}) async {
  final installRoot =
      Directory.fromUri(input.outputDirectoryShared.resolve('$cacheSubdir/'));
  final tripletRoot = installRoot.uri.resolve('$triplet/');
  final archive = File.fromUri(tripletRoot.resolve(archiveRelPath));
  final includeDir = Directory.fromUri(tripletRoot.resolve('include/'));
  if (archive.existsSync() && includeDir.existsSync()) {
    return (tripletRoot, archive.path);
  }

  final vcpkg = await _vcpkgExe(input);
  final manifestDir =
      input.packageRoot.resolve('$manifestRelPath/').toFilePath();
  await _serializeVcpkg(() => _runChecked(
        vcpkg,
        [
          'install',
          '--triplet=$triplet',
          if (overlayTriplets)
            '--overlay-triplets=${input.packageRoot.resolve('tool/vcpkg_triplets/').toFilePath()}',
          '--x-install-root=${installRoot.path}',
          '--no-print-usage',
        ],
        desc: 'vcpkg install $cacheSubdir ($triplet)',
        workingDirectory: manifestDir,
        environment: environment,
      ));
  if (!archive.existsSync()) {
    throw StateError(
        'vcpkg $cacheSubdir ($triplet) produced no ${archive.path}');
  }
  return (tripletRoot, archive.path);
}

/// In-process guard so a single build that drives several vcpkg consumers
/// concurrently (e.g. macOS libvpx + libopus) clones + bootstraps vcpkg
/// exactly once. Without it, the parallel first-time callers race on the
/// same `git clone` / bootstrap of the shared `vcpkg/` dir and one fails.
Future<String>? _vcpkgExeFuture;

/// Serialises `vcpkg install` invocations. vcpkg holds an exclusive lock on
/// its root's `buildtrees/` (`vcpkg-running.lock`), so two installs against
/// the same vcpkg clone can't run concurrently — and macOS builds libvpx +
/// libopus in parallel (likewise Windows for the two wrapper DLLs). Each
/// install still differs only in `--x-install-root`, so chaining them keeps
/// correctness while avoiding "another vcpkg may be running" lock failures.
/// The per-triplet result caches mean this chain runs each port just once.
Future<void> _vcpkgChain = Future<void>.value();
Future<T> _serializeVcpkg<T>(Future<T> Function() action) {
  final result = _vcpkgChain.then((_) => action());
  // Keep the chain alive even if an install fails, so a later install still
  // runs (and surfaces its own error) instead of inheriting this failure.
  _vcpkgChain = result.then((_) {}, onError: (_) {});
  return result;
}

/// Locates a `vcpkg` executable (`VCPKG_ROOT`, then PATH), else clones +
/// bootstraps microsoft/vcpkg into the shared cache. A full (non-shallow) clone
/// is required so the manifest's `builtin-baseline` commit is present.
Future<String> _vcpkgExe(BuildInput input) =>
    _vcpkgExeFuture ??= _vcpkgExeOnce(input);

Future<String> _vcpkgExeOnce(BuildInput input) async {
  final sep = Platform.pathSeparator;
  final exeName = Platform.isWindows ? 'vcpkg.exe' : 'vcpkg';
  final root = Platform.environment['VCPKG_ROOT'];
  if (root != null) {
    final p = '$root$sep$exeName';
    if (File(p).existsSync()) return p;
  }
  // Honour an already-installed vcpkg on PATH so a fresh build doesn't trigger
  // the multi-minute clone below.
  for (final dir in (Platform.environment['PATH'] ?? '').split(Platform.isWindows ? ';' : ':')) {
    if (dir.isEmpty) continue;
    final p = '$dir$sep$exeName';
    if (File(p).existsSync()) return p;
  }
  final vcpkgDir = Directory.fromUri(input.outputDirectoryShared.resolve('vcpkg/'));
  final exe = File.fromUri(vcpkgDir.uri.resolve(exeName));
  if (exe.existsSync()) return exe.path;
  if (!vcpkgDir.existsSync()) {
    await _runChecked('git',
        ['clone', 'https://github.com/microsoft/vcpkg.git', vcpkgDir.path],
        desc: 'git clone vcpkg');
  }
  if (Platform.isWindows) {
    await _runChecked(
        vcpkgDir.uri.resolve('bootstrap-vcpkg.bat').toFilePath(),
        ['-disableMetrics'],
        desc: 'bootstrap vcpkg', workingDirectory: vcpkgDir.path);
  } else {
    await _runChecked('bash',
        [vcpkgDir.uri.resolve('bootstrap-vcpkg.sh').toFilePath(), '-disableMetrics'],
        desc: 'bootstrap vcpkg', workingDirectory: vcpkgDir.path);
  }
  return exe.path;
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
// Windows source-builds the `webdartc_vp{8,9}.dll` wrappers from libvpx
// (pinned by `tool/libvpx_vcpkg/vcpkg.json`) via
// `tool/build_libvpx_wrappers.dart`, run under an MSVC environment by
// [_windowsWrapperSourceBuild]. Requires MSVC (vcvarsall.bat) — already a
// `flutter build windows` prerequisite. vcpkg is auto-bootstrapped by
// [_vcpkgExe] if absent.
//
// Bumping the libvpx pin: edit the libvpx version + `builtin-baseline` in
// `tool/libvpx_vcpkg/vcpkg.json`. The next build picks it up (the CI
// hook-artifact cache key hashes the manifest, so it re-builds).

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

  // Short-circuit on a cache hit: outDir lives under outputDirectoryShared,
  // which CI restores via actions/cache and which persists locally across
  // builds. If the wrapper DLL(s) are already there, skip the multi-minute
  // vcpkg source build + cl link entirely. The expensive vcpkg work writes
  // to `<manifest>/vcpkg_installed/` (outside the cache), so without this
  // guard every build would rebuild libvpx/opus from source.
  final dlls = outDir
      .listSync()
      .whereType<File>()
      .where((f) => f.uri.pathSegments.last.toLowerCase().endsWith('.dll'));
  if (dlls.isNotEmpty) return outDir.uri;

  final pkg = input.packageRoot;
  final scriptPath = pkg.resolve(scriptRelPath).toFilePath();
  final manifestDir = pkg.resolve(manifestRelPath).toFilePath();
  final srcDir = pkg.resolve('src').toFilePath();
  // Auto-bootstrap vcpkg (clone + bootstrap into the shared cache) if it
  // isn't on VCPKG_ROOT / PATH, matching the macOS / Linux codec paths.
  // build_*_wrappers.dart takes the path via --vcpkg.
  final vcpkg = await _vcpkgExe(input);
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
  // vcvarsall.bat is located via vswhere.exe (fixed Installer path on every
  // machine with VS), so this works regardless of edition — Community /
  // Professional / Enterprise (e.g. GitHub's windows runners) or the
  // standalone Build Tools — rather than assuming one hardcoded install dir.
  // `-find` returns the vcvarsall.bat path directly: no `-requires` component
  // id (which differs by host arch — x64 vs ARM64 toolset) and no manual path
  // join. `-prerelease` covers preview VS installs on some runner images.
  // Requires the VC++ toolset, which `flutter build windows` already needs.
  //
  // `dart <script>` (no `run`) executes the script directly — `dart run`
  // would recursively re-enter `package:hooks_runner` and deadlock on
  // the same `.lock` file this hook is already holding.
  final vcvarsArch = _vcvarsArchArg(arch);
  // Place the launcher .bat outside outDir so it survives the wrapper
  // script's post-run cleanup of non-DLL files — otherwise cmd loses
  // the file mid-execution and reports "batch file not found".
  final batPath = input.outputDirectory
      .resolve('$label-source-build-$triplet.bat')
      .toFilePath();
  File(batPath).writeAsStringSync(
    '@echo off\r\n'
    'set "VCVARSALL="\r\n'
    // vswhere.exe ships with the VS Installer at this fixed location on every
    // edition. Hardcoded (not via %ProgramFiles(x86)%) because hooks_runner
    // scrubs the environment before invoking the hook, so that var may be unset.
    'set "VSWHERE=C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe"\r\n'
    'if exist "%VSWHERE%" (\r\n'
    '  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -products * '
    '-find "VC\\Auxiliary\\Build\\vcvarsall.bat"`) do set "VCVARSALL=%%i"\r\n'
    ')\r\n'
    'if not defined VCVARSALL (echo could not locate vcvarsall.bat via "%VSWHERE%" - install the Visual Studio "Desktop development with C++" workload 1>&2 & exit /b 1)\r\n'
    'call "%VCVARSALL%" $vcvarsArch\r\n'
    'if errorlevel 1 exit /b 1\r\n'
    '"${Platform.resolvedExecutable}" "$scriptPath"'
    ' --triplet=$triplet'
    ' --vcpkg="$vcpkg"'
    ' --manifest-dir="$manifestDir"'
    ' --src-dir="$srcDir"'
    ' --out-dir="$outPath"\r\n',
  );
  // The script runs `vcpkg install` internally, so serialise the whole
  // wrapper build against the other codec's (libvpx vs libopus run in
  // parallel) to avoid vcpkg's buildtrees lock contention.
  await _serializeVcpkg(() => _runChecked('cmd', ['/c', batPath],
      desc: '$label wrapper source build ($triplet)'));

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
// Same shape as the libvpx Windows section above: Windows source-builds
// `webdartc_opus.dll` from libopus (pinned by
// `tool/libopus_vcpkg/vcpkg.json`) via `tool/build_libopus_wrappers.dart`
// under MSVC. Bump the pin by editing the libopus version +
// `builtin-baseline` in that manifest.

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
