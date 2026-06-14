# webdartc

A WebRTC stack written natively in Dart.

This monorepo holds two packages: a pure-Dart protocol library and the Flutter
integration that renders its media on screen.

| Package | What it is | Status |
|---|---|---|
| [`dart/`](dart) | The WebRTC library. W3C `PeerConnection` API on top of RFC-compliant protocol state machines (STUN / ICE / TURN / DTLS / SRTP / SCTP / RTP / SDP), with UDP handled by `TransportController`. Codecs (H.264 / VP8 / VP9 / Opus) and crypto run through platform-native libraries via FFI. | Implemented |
| [`flutter/`](flutter) | Rendering and capture on top of `dart`. A `Texture`-backed video widget — Metal `CVPixelBuffer` on macOS, `PixelBufferTexture` on Windows — plus camera/mic/speaker integration. Depends on `dart` via a local `path:`. | macOS + Windows renderers working; Linux/mobile on the roadmap |

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
│   └── example/               #   macOS demo app (browser ↔ Flutter call)
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

Every backend is software except VideoToolbox on macOS, which is hardware-accelerated.

| Codec | macOS | Linux | Windows |
|-------|-------|-------|---------|
| H.264 | VideoToolbox (HW) | OpenH264 (Cisco prebuilt) | OpenH264 (Cisco prebuilt) |
| VP8 / VP9 | libvpx (submodule, source-built) | libvpx (submodule, source-built) | prebuilt wrapper DLL (source build opt-in) |
| Opus | libopus (submodule, source-built) | libopus (submodule, source-built) | prebuilt wrapper DLL (source build opt-in) |

`registerH264Codec()` / `registerVp8Codec()` / `registerVp9Codec()` /
`registerOpusCodec()` each pick the right backend for the host automatically.
[`dart/hook/build.dart`](dart/hook/build.dart) drives every native asset:
compiles the VideoToolbox C shim on macOS, source-builds libopus + libvpx from
the submodules on macOS / Linux, downloads our prebuilt wrapper DLLs on Windows,
and fetches Cisco's OpenH264 (version + SHA-256 pinned) on Linux + Windows. The
full per-OS breakdown and symbol-hiding rationale live in
[`dart/README.md#codec-backends`](dart/README.md#codec-backends).

### Native requirements

- **macOS** — Xcode (CoreMedia / VideoToolbox frameworks) and CMake
  (`brew install cmake`). NASM (`brew install nasm`) is only needed for the
  x86_64 slice of a universal build. `flutter pub get` + `dart test` handle the rest.
- **Linux** — `sudo apt-get install cmake clang nasm libssl-dev` (build libopus,
  assemble libvpx's x86_64 SIMD, OpenSSL for crypto). Codecs are vendored or
  downloaded — no system codec packages needed.
- **Windows** — nothing for the default path: `flutter pub get` downloads the
  VP8 / VP9 / Opus wrapper DLLs and the Cisco OpenH264 binary, and the OS's CNG
  (`bcrypt.dll`) provides crypto. The source-build opt-in needs MSVC + vcpkg.

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
