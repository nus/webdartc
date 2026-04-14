# webdartc monorepo

A Dart-native WebRTC stack. This monorepo contains the protocol library and its Flutter integration layer.

## Packages

| Package | Purpose | Status |
|---|---|---|
| [`webdartc/`](webdartc) | Pure-Dart WebRTC library. RFC-compliant protocol state machines (ICE / DTLS / SRTP / SCTP / RTP / SDP) with all network I/O isolated to a single `TransportController`. Platform-native crypto via FFI (CommonCrypto on macOS, OpenSSL on Linux). Supports data channels and media send/receive. | Implemented |
| [`webdartc_flutter/`](webdartc_flutter) | Flutter integration on top of `webdartc`. Provides a video-rendering `Widget`, audio/video encode/decode, camera and microphone capture, and speaker playback. Depends on `webdartc` via path. | Skeleton — in progress |

## Layout

```
.
├── webdartc/               # pure-Dart protocol library (Dart SDK ≥ 3.11)
│   ├── lib/                #   peer_connection, transport, ice, dtls, srtp,
│   │                       #   sctp, stun, rtp, sdp, crypto, media, codec, core
│   ├── test/               #   unit + fuzz + e2e (Chrome / Firefox WebDriver)
│   └── example/
├── webdartc_flutter/       # Flutter integration (requires Flutter SDK)
│   └── lib/webdartc_flutter.dart
├── CLAUDE.md               # agent guidance for this repo
└── README.md
```

## Working in this repo

This repo is configured as a [pub workspace](https://dart.dev/tools/pub/workspaces): a single resolution covers both packages. Cloning and running `pub get` at the root resolves everything in one pass.

```bash
git clone <repo-url> webdartc
cd webdartc
flutter pub get        # resolves webdartc + webdartc_flutter together
```

> **Flutter SDK is required at the repo root** because `webdartc_flutter` depends on the Flutter SDK. Use `flutter pub get` (not `dart pub get`) from the workspace root. If you only need the pure-Dart library, depend on `webdartc` from your own project — you do not need to clone this repo.

Once resolved, each package is worked on from its own directory:

```bash
# Protocol library
cd webdartc
dart test              # unit tests
dart test test/e2e/    # e2e (Chrome / Firefox)
dart analyze

# Flutter integration
cd webdartc_flutter
flutter test
flutter analyze
```

`webdartc_flutter` depends on `webdartc` via a local `path:` reference, so changes in `webdartc/` are picked up without republishing.

## Scope of `webdartc_flutter`

Responsibilities this package owns (and `webdartc` deliberately does not):

- **Rendering** — a Flutter `Widget` that renders decoded video frames produced by `webdartc`'s media pipeline.
- **Codec** — audio/video encode and decode (e.g. Opus, VP8/VP9, H.264) bridging platform codecs to `webdartc`'s `MediaStreamTrack`.
- **Capture** — camera and microphone input, exposed as `MediaStreamTrack`s consumable by `PeerConnection`.
- **Playback** — routing remote audio to the speaker / audio output device.

The `webdartc` package remains free of `dart:ui`, Flutter, and platform capture/playback dependencies.

## License

See [`webdartc/LICENSE.txt`](webdartc/LICENSE.txt).
