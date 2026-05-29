# webdartc_flutter example

macOS app that acts as a full WebRTC peer, exercising the `webdartc`
protocol stack and the `webdartc_flutter` renderer end-to-end:

```
                 ┌────────────────── Flutter peer (this app) ──────────────────┐
Outgoing (Flutter → peer):
  FakeVideoSource → VideoToolbox H.264 encoder → H264Packetizer
                  → PeerConnection.sendRtp → SRTP/DTLS/ICE → UDP
                                                              ↓
Incoming (peer → Flutter):                                    UDP
  PeerConnection.onTrack → H264Depacketizer → VideoToolbox decoder
                         → ShaderVideoRenderer (Metal texture)
                 └──────────────────────────────────────────────────────────────┘
```

The UI shows two 320×240 tiles side-by-side:

| Tile | Source |
|------|--------|
| `local`  | Raw `FakeVideoSource` frames rendered before encoding — serves as a "preview" of what's being sent. |
| `remote` | Incoming peer camera stream after depacketization and VT decoding. |

Frame counters (`sent=N`, `recv=N`) appear both in the AppBar and below each
tile's label.

## Signaling

The app speaks the [OpenAyame](https://github.com/OpenAyame/ayame-spec)
signaling protocol: register with a `roomId` (+ optional
`signalingKey`), receive `accept` with role assignment + `iceServers`,
then exchange `offer` / `answer` / `candidate`. The launch screen has
input fields for the **Signaling URL**, **Room ID**, and a **Signaling
key**; defaults can be pre-populated via `--dart-define=AYAME_URL=...`,
`--dart-define=AYAME_ROOM=...`, `--dart-define=AYAME_SIGNALING_KEY=...`.

The default Signaling URL is `ws://127.0.0.1:8080/signaling` — i.e. the
local Ayame relay shipped in `dart/example/signaling/server.dart`. Point
it at a hosted Ayame instead by editing the form or passing
`--dart-define=AYAME_URL=wss://ayame.example.com/signaling`.

## Run (browser ↔ Flutter via local signaling)

Terminal 1 — local Ayame relay + browser HTML:

```bash
cd dart
dart run example/signaling/server.dart --port=8080
```

Terminal 2 — open the browser (grant camera permission):

```
http://127.0.0.1:8080/?room=webdartc-demo
```

Terminal 3 — Flutter app:

```bash
cd flutter/example
flutter run -d macos
# Tap "Join" with default URL/room — pairs with the browser.
```

## Run (against a hosted OpenAyame server)

Replace the URL in the form, or:

```bash
cd flutter/example
flutter run -d macos --dart-define=AYAME_URL=wss://ayame.example.com/signaling
```

Two clients joining the same `roomId` form a call.

## E2E auto-mode

`WEBDARTC_PORT=N` in the environment skips the form and auto-joins
`ws://127.0.0.1:N/signaling` (room=`webdartc-demo`). The
`flutter_video_call_bidir_test.dart` e2e harness drives the app this
way.

Requires Xcode and CocoaPods (`brew install cocoapods`). The VideoToolbox C
helper is compiled automatically by `dart/hook/build.dart` during the build.

## What it verifies

- `dart/hook/build.dart` produces a loadable `.dylib` bundled into the app.
- Swift `FlutterTexture` plugin (`flutter/macos/Classes/WebdartcFlutterPlugin.swift`)
  receives frames over the method channel, converts I420 → NV12
  `CVPixelBuffer`, and hands them to Flutter's Metal compositor.
- End-to-end bidirectional video over real DTLS/SRTP/ICE with `sent`
  and `recv` counters both advancing.
- macOS sandbox entitlements permit WebSocket + UDP
  (`com.apple.security.network.client` / `network.server`).
