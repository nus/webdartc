# webdartc monorepo

A Dart-native WebRTC stack. This monorepo contains the protocol library and its Flutter integration layer.

## Packages

| Package | Purpose | Status |
|---|---|---|
| [`dart/`](dart) | Pure-Dart WebRTC library. RFC-compliant protocol state machines (ICE / DTLS / SRTP / SCTP / RTP / SDP) with all network I/O isolated to a single `TransportController`. Codec backends via FFI (H.264 via VideoToolbox on Apple / Cisco-prebuilt OpenH264 on Linux + Windows, VP8 + VP9 + Opus via vendored libvpx + libopus — source-built on macOS / Linux, downloaded as wrapper DLLs on Windows). Platform-native crypto (CommonCrypto + Security.framework on macOS, OpenSSL on Linux, CNG / `bcrypt.dll` on Windows). | Implemented |
| [`flutter/`](flutter) | Flutter integration on top of `dart`. Provides a Metal-backed video-rendering `Widget` on macOS and a `PixelBufferTexture`-backed renderer on Windows, with Linux GLES support on the roadmap. Depends on `dart` via path. | macOS + Windows renderers working; other platforms in progress |

## Layout

```
.
├── dart/                     # pure-Dart protocol library (Dart SDK ≥ 3.11)
│   ├── hook/build.dart       #   compiles the VideoToolbox C helper (Apple)
│   │                         #   and the vendored libopus + libvpx
│   │                         #   (macOS + Linux); downloads prebuilt
│   │                         #   wrapper DLLs + Cisco OpenH264 (Windows)
│   │                         #   and Cisco OpenH264 (Linux)
│   ├── src/                  #   C sources built by the hook
│   ├── third_party/opus/     #   libopus submodule (statically linked)
│   ├── third_party/libvpx/   #   libvpx submodule (statically linked,
│   │                         #   shared between webdartc_vp8 + webdartc_vp9)
│   ├── lib/                  #   peer_connection, transport, ice, dtls, srtp,
│   │                         #   sctp, stun, rtp, sdp, crypto, media, codec, core
│   ├── test/                 #   unit + fuzz + e2e (Chrome / Firefox)
│   └── example/             #   video_sender / video_receiver / audio_send /
│                             #   audio_receive / signaling (for Flutter pairing)
├── flutter/                  # Flutter integration (requires Flutter SDK)
│   ├── lib/render/           #   VideoRenderer / ShaderVideoRenderer / widget
│   ├── macos/Classes/        #   Swift FlutterTexture plugin
│   └── example/              #   runnable macOS demo app
├── .github/workflows/ci.yaml # Linux + macOS + Windows CI
│                             # (analyze, unit, E2E, flutter test + build)
├── CLAUDE.md                 # agent guidance for this repo
└── README.md
```

## Working in this repo

This repo is configured as a [pub workspace](https://dart.dev/tools/pub/workspaces): a single resolution covers both packages.

```bash
git clone --recurse-submodules <repo-url> webdartc
cd webdartc
flutter pub get        # resolves dart + flutter together
```

> If you cloned without `--recurse-submodules`, run `git submodule update --init --recursive` before building — `dart/third_party/opus/` and `dart/third_party/libvpx/` are submodules that the build hook needs.

> **Flutter SDK is required at the repo root** because the `flutter` package depends on the Flutter SDK. Use `flutter pub get` (not `dart pub get`) from the workspace root. If you only need the pure-Dart library, depend on `webdartc` from your own project — you do not need to clone this repo.

Once resolved, each package is worked on from its own directory:

```bash
# Protocol library
cd dart
dart test                      # unit tests (runs the build hook on macOS / Linux / Windows)
dart test test/e2e/            # e2e (Chrome / Firefox auto-downloaded)
dart analyze

# Flutter integration
cd flutter
flutter test                   # widget tests with a mock MethodChannel
flutter analyze

# Flutter macOS demo (full Flutter ↔ browser WebRTC peer)
cd flutter/example
flutter run -d macos           # pair with dart/example/signaling (Ayame) + Chrome
```

The `flutter` package depends on `dart` via a local `path:` reference, so changes in `dart/` are picked up without republishing.

## Codec matrix

All backends are software (SW) except VideoToolbox on macOS, which is hardware-accelerated.

| Codec | macOS | Linux | Windows |
|-------|-------|-------|---------|
| H.264 | VideoToolbox (HW) | OpenH264 (Cisco prebuilt) | OpenH264 (Cisco prebuilt) |
| VP8 / VP9 | libvpx (submodule source-built) | libvpx (submodule source-built) | libvpx (prebuilt wrapper DLL; source-build opt-in) |
| Opus | libopus (submodule source-built) | libopus (submodule source-built) | libopus (prebuilt wrapper DLL; source-build opt-in) |

`registerH264Codec()` / `registerVp8Codec()` / `registerVp9Codec()` / `registerOpusCodec()` each pick the right backend for the current platform automatically. `dart/hook/build.dart` drives every native asset: it compiles the VideoToolbox C shim on macOS, source-builds libopus + libvpx from submodules on macOS / Linux, downloads our prebuilt wrapper DLLs on Windows (`webdartc-lib{vpx,opus}-prebuilt-*` release assets — set `hooks.user_defines.webdartc.lib{vpx,opus}_source_build=true` in the workspace-root `pubspec.yaml` to opt into a local MSVC + vcpkg build), and downloads Cisco's OpenH264 binary from `ciscobinary.openh264.org` (version + SHA-256 pinned) on Linux + Windows. See [`dart/README.md#codec-backends`](dart/README.md#codec-backends) for the full per-OS breakdown and the symbol-hiding rationale, and https://www.openh264.org/ for OpenH264's upstream distribution terms.

### Native library requirements

- **macOS**: Xcode (for CoreMedia / VideoToolbox frameworks) and CMake (`brew install cmake`). `dart pub get` + `dart test` handle the rest.
- **Linux**: `sudo apt-get install cmake clang yasm libssl-dev` (CMake + clang to build bundled libopus, yasm for libvpx's x86_64 SIMD, OpenSSL for crypto). VP8 / VP9 / Opus are vendored; OpenH264 is downloaded by the build hook on first run — no system codec packages needed.
- **Windows**: nothing to install for the default path — `dart pub get` downloads the prebuilt wrapper DLLs for VP8 / VP9 / Opus + the Cisco OpenH264 binary, and the OS-built-in CNG (`bcrypt.dll`) provides the crypto primitives. The source-build opt-in requires MSVC + vcpkg.

## Scope of `flutter`

Responsibilities this package owns (and `dart` deliberately does not):

- **Rendering** — a `VideoRendererWidget` backed by Flutter's `Texture`. On macOS the plugin converts decoded I420 frames to NV12 `CVPixelBuffer`; Flutter's Metal compositor samples it with its built-in YUV→RGB shader.
- **Capture / playback** — camera, microphone, and speaker integration (roadmap; platform-native where possible via FFI, Flutter plugin where not).

The `dart` package remains free of `dart:ui`, Flutter, and platform capture/playback dependencies.

## License

See [`dart/LICENSE.txt`](dart/LICENSE.txt).
