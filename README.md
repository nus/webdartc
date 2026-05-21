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
│   └── example/
│       └── video_call/       #   browser ↔ Dart sendonly / bidir demo
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
dart test                      # unit tests (runs the macOS build hook if applicable)
dart test test/e2e/            # e2e (Chrome / Firefox auto-downloaded)
dart analyze

# Flutter integration
cd flutter
flutter test                   # widget tests with a mock MethodChannel
flutter analyze

# Flutter macOS demo (full Flutter ↔ browser WebRTC peer)
cd flutter/example
flutter run -d macos           # pair with dart/example/video_call server + Chrome ?bidir=1
```

The `flutter` package depends on `dart` via a local `path:` reference, so changes in `dart/` are picked up without republishing.

## Codec matrix

| Codec | macOS | Linux | Windows |
|-------|-------|-------|---------|
| H.264 | VideoToolbox (HW) | OpenH264 (Cisco prebuilt, bundled, SW) | OpenH264 (Cisco prebuilt, bundled, SW) |
| VP8   | libvpx (source-built from submodule, SW) | libvpx (source-built from submodule, SW) | libvpx (wrapper DLL downloaded, SW; source-build opt-in) |
| VP9   | libvpx (source-built from submodule, SW) | libvpx (source-built from submodule, SW) | libvpx (wrapper DLL downloaded, SW; source-build opt-in) |
| Opus  | libopus (source-built from submodule, SW) | libopus (source-built from submodule, SW) | libopus (wrapper DLL downloaded, SW; source-build opt-in) |

`registerH264Codec()` / `registerVp8Codec()` / `registerVp9Codec()` / `registerOpusCodec()` each pick the right backend for the current platform automatically. The VideoToolbox helper is a small C shim compiled by `dart/hook/build.dart` — no manual build step required. On **macOS and Linux**, libopus + libvpx are vendored as submodules and statically linked into per-codec wrapper shared libraries (`webdartc_codecs` for opus, `webdartc_vp8` and `webdartc_vp9` for VP8/VP9) by the same hook. On **Windows**, the default path downloads the same wrapper DLLs prebuilt on GitHub Actions (`webdartc-libvpx-prebuilt-*` and `webdartc-libopus-prebuilt-*` release assets) and registers them as code assets — no MSVC / vcpkg required on the consumer machine. The source-build opt-in is reachable per package via `hooks.user_defines.webdartc.libvpx_source_build` / `libopus_source_build` in the workspace-root `pubspec.yaml`. The same hidden-symbol pattern applies regardless of source vs prebuilt: only the `webdartc_*` wrapper functions are exported, so the bundled copies can't collide with another libopus / libvpx loaded into the same process. On **Linux and Windows**, `dart/hook/build.dart` additionally downloads Cisco's prebuilt OpenH264 binary from `ciscobinary.openh264.org` (pinned by version + SHA-256) and registers it as a code asset — no system H.264 install needed. See https://www.openh264.org/ for the upstream project's distribution terms.

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
