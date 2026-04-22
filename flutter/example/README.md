# webdartc_flutter example

macOS app that acts as a full WebRTC peer against a browser, exercising the
`webdartc` protocol stack and the `webdartc_flutter` renderer end-to-end:

```
                 ┌────────────────── Flutter peer (this app) ──────────────────┐
Outgoing (Flutter → browser):
  FakeVideoSource → VideoToolbox H.264 encoder → H264Packetizer
                  → PeerConnection.sendRtp → SRTP/DTLS/ICE → UDP
                                                              ↓
Incoming (browser → Flutter):                                 UDP
  PeerConnection.onTrack → H264Depacketizer → VideoToolbox decoder
                         → ShaderVideoRenderer (Metal texture)
                 └──────────────────────────────────────────────────────────────┘
```

The UI shows two 320×240 tiles side-by-side:

| Tile | Source |
|------|--------|
| `local`  | Raw `FakeVideoSource` frames rendered before encoding — serves as a "preview" of what's being sent. |
| `remote` | Incoming browser camera stream after depacketization and VT decoding. |

Frame counters (`sent=N`, `recv=N`) appear both in the AppBar and below each
tile's label.

## Run

You need the Dart signaling server and a browser peer from
`dart/example/video_call/`.

Terminal 1 — signaling + static HTTP server:

```bash
cd dart
dart run example/video_call/bin/server.dart --port=8080
```

Terminal 2 — browser (grant camera permission):

```
http://127.0.0.1:8080/?bidir=1
```

Terminal 3 — Flutter app:

```bash
cd flutter/example
WEBDARTC_PORT=8080 flutter run -d macos    # or just: flutter run -d macos
```

Requires Xcode and CocoaPods (`brew install cocoapods`). The VideoToolbox C
helper is compiled automatically by `dart/hook/build.dart` during the build.

## What it verifies

- `dart/hook/build.dart` produces a loadable `.dylib` bundled into the app.
- Swift `FlutterTexture` plugin (`flutter/macos/Classes/WebdartcFlutterPlugin.swift`)
  receives frames over the method channel, converts I420 → NV12
  `CVPixelBuffer`, and hands them to Flutter's Metal compositor.
- End-to-end bidirectional video: browser ↔ Flutter peer over real
  DTLS/SRTP/ICE, with `sent` and `recv` counters both advancing.
- macOS sandbox entitlements permit WebSocket + UDP
  (`com.apple.security.network.client` / `network.server`).
