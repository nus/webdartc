# webdartc monorepo

A Dart-native WebRTC stack. This monorepo contains the protocol library and its Flutter integration layer.

## Packages

| Package | Purpose | Status |
|---|---|---|
| [`dart/`](dart) | Pure-Dart WebRTC library. RFC-compliant protocol state machines (ICE / DTLS / SRTP / SCTP / RTP / SDP) with all network I/O isolated to a single `TransportController`. Codec backends via FFI (VP8 / H.264 / VideoToolbox on Apple, Opus via vendored libopus). Platform-native crypto (CommonCrypto on macOS, OpenSSL on Linux). | Implemented |
| [`flutter/`](flutter) | Flutter integration on top of `dart`. Provides a Metal-backed video-rendering `Widget` (macOS), with Linux GLES and iOS support on the roadmap. Depends on `dart` via path. | macOS renderer working; other platforms in progress |

## Layout

```
.
├── dart/                     # pure-Dart protocol library (Dart SDK ≥ 3.11)
│   ├── hook/build.dart       #   compiles the VideoToolbox C helper (Apple)
│   │                         #   and the vendored libopus (macOS + Linux)
│   ├── src/                  #   C sources built by the hook
│   ├── third_party/opus/     #   libopus submodule (statically linked)
│   ├── lib/                  #   peer_connection, transport, ice, dtls, srtp,
│   │                         #   sctp, stun, rtp, sdp, crypto, media, codec, core
│   ├── test/                 #   unit + fuzz + e2e (Chrome / Firefox)
│   └── example/
│       └── video_call/       #   browser ↔ Dart sendonly / bidir demo
├── flutter/                  # Flutter integration (requires Flutter SDK)
│   ├── lib/render/           #   VideoRenderer / ShaderVideoRenderer / widget
│   ├── macos/Classes/        #   Swift FlutterTexture plugin
│   └── example/              #   runnable macOS demo app
├── .github/workflows/ci.yaml # Linux + macOS CI (analyze, unit, E2E, flutter build)
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

> If you cloned without `--recurse-submodules`, run `git submodule update --init --recursive` before building — `dart/third_party/opus/` is a submodule that the build hook needs.

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

| Codec | macOS / iOS | Linux | Windows |
|-------|-------------|-------|---------|
| H.264 | VideoToolbox (HW) | OpenH264 (SW) | OpenH264 (SW) |
| VP8   | libvpx (SW) | libvpx (SW) | libvpx (SW) |
| Opus  | libopus (bundled, SW) | libopus (bundled, SW) | — (roadmap) |

`registerH264Codec()` picks the right backend for the current platform automatically. The VideoToolbox helper is a ~500-line C shim compiled by `dart/hook/build.dart` — no manual build step required. libopus is vendored under `dart/third_party/opus/` and statically linked into a single `webdartc_codecs` shared library by the same build hook (only the wrapper symbols are exported, so the bundled copy can't collide with another libopus loaded into the same process).

### Native library requirements

- **macOS / iOS**: Xcode (for CoreMedia / VideoToolbox frameworks) and CMake (`brew install cmake`). `dart pub get` + `dart test` handle the rest.
- **Linux**: `sudo apt-get install cmake clang libssl-dev libvpx-dev libopenh264-dev` (CMake + clang to build the bundled libopus; OpenSSL, VP8, and H.264 are still consumed from the system).

## Scope of `flutter`

Responsibilities this package owns (and `dart` deliberately does not):

- **Rendering** — a `VideoRendererWidget` backed by Flutter's `Texture`. On macOS the plugin converts decoded I420 frames to NV12 `CVPixelBuffer`; Flutter's Metal compositor samples it with its built-in YUV→RGB shader.
- **Capture / playback** — camera, microphone, and speaker integration (roadmap; platform-native where possible via FFI, Flutter plugin where not).

The `dart` package remains free of `dart:ui`, Flutter, and platform capture/playback dependencies.

## License

See [`dart/LICENSE.txt`](dart/LICENSE.txt).
