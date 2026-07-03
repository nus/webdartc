# webdartc

A WebRTC stack written natively in Dart.

This monorepo holds two packages: a pure-Dart protocol library and the Flutter
integration that renders its media on screen.

| Package | What it is | Status |
|---|---|---|
| [`dart/`](dart) | The WebRTC library. W3C `PeerConnection` API on top of RFC-compliant protocol state machines (STUN / ICE / TURN / DTLS / SRTP / SCTP / RTP / SDP), with UDP handled by `TransportController`. Codecs (H.264 / VP8 / VP9 / Opus) and crypto run through platform-native libraries via FFI. | Implemented |
| [`flutter/`](flutter) | Rendering and capture on top of `dart`. A `Texture`-backed video widget — Metal `CVPixelBuffer` on macOS, `PixelBufferTexture` on Windows, `SurfaceTexture` on Android — plus camera/mic/speaker integration. Depends on `dart` via a local `path:`. | macOS + Windows + Android renderers working; iOS / Linux on the roadmap |

## Quick start

```bash
git clone --recurse-submodules https://github.com/nus/webdartc.git
cd webdartc
flutter pub get          # one resolution covers both packages (pub workspace)
```

The repo is a [pub workspace](https://dart.dev/tools/pub/workspaces), so a single
`flutter pub get` at the root resolves `dart` and `flutter` together. Use
`flutter pub get` (not `dart pub get`) because the `flutter` package needs the
Flutter SDK.

> Cloned without `--recurse-submodules`? Run
> `git submodule update --init --recursive` first — the build hook source-builds
> the `dart/third_party/opus` and `dart/third_party/libvpx` submodules on
> macOS / Linux.
>
> Only need the protocol library? Depend on `webdartc` from your own
> project — you don't have to clone this repo.

## Layout

```
.
├── dart/                      # pure-Dart WebRTC library (Dart SDK ≥ 3.11)
│   ├── lib/                   #   peer_connection, transport, ice, turn, dtls,
│   │                          #   srtp, sctp, stun, rtp, sdp, crypto, media,
│   │                          #   codec, api, core
│   ├── hook/build.dart        #   native-asset build hook (codecs + VT shim)
│   ├── src/                   #   C sources compiled by the hook
│   ├── third_party/           #   libopus + libvpx submodules (static, hidden syms)
│   ├── test/                  #   unit + fuzz + e2e (Chrome / Firefox)
│   └── example/               #   runnable demos (see dart/README.md)
├── flutter/                   # Flutter integration (needs the Flutter SDK)
│   ├── lib/render/            #   VideoRenderer / ShaderVideoRenderer / widget
│   ├── macos/Classes/         #   Swift FlutterTexture plugin
│   └── example/               #   macOS + Android demo app (browser ↔ Flutter call)
├── .github/workflows/ci.yaml  # Linux + macOS + Windows CI
├── CLAUDE.md                  # agent guidance for this repo
└── README.md
```

## Working in the repo

Each package is driven from its own directory:

```bash
# Protocol library
cd dart
dart test                 # unit tests (build hook runs on macOS / Linux / Windows)
dart test test/e2e/       # browser e2e (Chrome / Firefox auto-downloaded)
dart analyze

# Flutter integration
cd flutter
flutter test              # widget tests against a mock MethodChannel
flutter analyze

# Flutter macOS demo — a full Flutter ↔ browser WebRTC call
cd flutter/example
flutter run -d macos      # pair with dart/example/signaling (OpenAyame) + a browser
```

Because `flutter` depends on `dart` via `path:`, edits in `dart/` are picked up
without republishing.

## Codec matrix

Every backend is software except VideoToolbox on macOS and MediaCodec on
Android, which use the OS-provided codec (hardware-accelerated where the device
offers it).

| Codec | macOS | Linux | Windows | Android |
|-------|-------|-------|---------|---------|
| H.264 | VideoToolbox (HW) | OpenH264 (Cisco prebuilt) | OpenH264 (Cisco prebuilt) | MediaCodec (NDK `AMediaCodec` via FFI) |
| VP8 / VP9 | libvpx (vcpkg, source-built) | libvpx (submodule, source-built) | libvpx (vcpkg, source-built) | MediaCodec (NDK `AMediaCodec` via FFI) |
| Opus | libopus (vcpkg, source-built) | libopus (submodule, source-built) | libopus (vcpkg, source-built) | libopus (submodule, source-built via NDK) |

`registerH264Codec()` / `registerVp8Codec()` / `registerVp9Codec()` /
`registerOpusCodec()` each pick the right backend for the host automatically.
[`dart/hook/build.dart`](dart/hook/build.dart) drives every native asset:
compiles the VideoToolbox C shim on macOS, source-builds libopus + libvpx via
vcpkg on macOS / Windows and from the submodules on Linux (and via the NDK on
Android), and fetches Cisco's OpenH264 (version + SHA-256 pinned) on Linux +
Windows. Android H.264 needs no native asset — it binds the system
`libmediandk.so` (`AMediaCodec`) directly via pure-Dart FFI. The full per-OS
breakdown and symbol-hiding rationale live in
[`dart/README.md#codec-backends`](dart/README.md#codec-backends).

### Native requirements

- **macOS** — Xcode (CoreMedia / VideoToolbox frameworks). libvpx + libopus are
  source-built via vcpkg, which the build hook clones + bootstraps itself (or
  honours `VCPKG_ROOT`) and which brings its own CMake. NASM (`brew install nasm`)
  is only needed for the x86_64 slice of a universal build (libvpx SIMD).
  `flutter pub get` + `dart test` handle the rest.
- **Linux** — `sudo apt-get install cmake clang nasm pkg-config` (build libopus,
  assemble libvpx's x86_64 SIMD; pkg-config for vcpkg's BoringSSL port). Codecs
  are vendored/downloaded; BoringSSL (crypto) is source-built via vcpkg, which
  the build hook clones + bootstraps itself (or honours `VCPKG_ROOT`).
- **Windows** — MSVC (Visual Studio "Desktop development with C++", already
  required by `flutter build windows`) to source-build the VP8 / VP9 / Opus
  wrapper DLLs from libvpx / libopus via vcpkg, which the build hook clones +
  bootstraps itself (or honours `VCPKG_ROOT`). The Cisco OpenH264 binary is
  downloaded, and the OS's CNG (`bcrypt.dll`) provides crypto.
- **Android** — the Flutter Android toolchain (SDK + NDK + CMake, e.g. via
  Android Studio) plus pkg-config. The build hook cross-compiles libvpx +
  libopus with the NDK (VP8 / VP9 / Opus) and source-builds BoringSSL (crypto)
  via vcpkg per ABI. H.264 uses the system MediaCodec (`AMediaCodec`) via FFI,
  so it needs no build step.

## What `flutter` owns

Responsibilities the `flutter` package keeps out of `dart`, so the protocol
library stays free of `dart:ui` and platform UI/capture dependencies:

- **Rendering** — a `VideoRendererWidget` backed by Flutter's `Texture`. On
  macOS the plugin converts decoded I420 frames to NV12 `CVPixelBuffer` for
  Flutter's Metal compositor.
- **Capture / playback** — camera, microphone, and speaker integration
  (platform-native via FFI where possible, a Flutter plugin where not).

## License

See [`LICENSE.txt`](LICENSE.txt). Bundled/downloaded third-party codec licenses
are catalogued in
[`dart/THIRD_PARTY_NOTICES.md`](dart/THIRD_PARTY_NOTICES.md).
