# webdartc_flutter example

macOS / Windows / Linux / Android app that acts as a full WebRTC peer,
exercising the `webdartc` protocol stack and the `webdartc_flutter`
renderer end-to-end (shown here with macOS's codec backend; Windows and
Linux use OpenH264, Android uses MediaCodec):

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

On launch the app also starts an **embedded relay**
(`lib/embedded_signaling.dart`, same protocol subset as
`dart/example/signaling/server.dart`) on port 8080 and serves the
browser peer page (`assets/browser_peer.html`) on it, so no separate
server process is needed. If 8080 is taken it falls back to 8081–8083
(the form's URL follows); if all are taken it assumes an external relay
is running and just joins it. The default Signaling URL is
`ws://127.0.0.1:8080/signaling`, matching both the embedded relay and
`dart/example/signaling/server.dart`. Point the app at a hosted Ayame
instead by editing the form or passing
`--dart-define=AYAME_URL=wss://ayame.example.com/signaling`.

## Run (browser ↔ Flutter)

```bash
cd flutter/example
flutter run -d macos          # or: -d windows / -d linux / -d <android-device>
```

Then:

1. Open the URL shown on the app's launch screen (normally
   `http://127.0.0.1:8080/`) in a browser and grant camera permission.
   For a browser on a different machine than the app (e.g. Android
   phone), use one of the LAN URLs the app lists.
2. Press **Join** in the app (defaults are pre-filled — the browser
   page auto-joins the same room `webdartc-demo`).

The browser shows the app's generated test pattern, the app's `remote`
tile shows your camera, and `sent` / `recv` counters advance on both
sides.

## Run (against a hosted OpenAyame server)

Replace the URL in the form, or:

```bash
cd flutter/example
flutter run -d macos --dart-define=AYAME_URL=wss://ayame.example.com/signaling
```

Two clients joining the same `roomId` form a call.

## E2E auto-mode

`WEBDARTC_PORT=N` in the environment skips the form and the embedded
relay, and auto-joins `ws://127.0.0.1:N/signaling`
(room=`webdartc-demo`). The `flutter_video_call_bidir_test.dart` e2e
harness drives the app this way with its own relay.

Prereqs are the per-OS native toolchains listed in the root README's
"Native requirements" (macOS additionally needs CocoaPods:
`brew install cocoapods`). All native codec assets — the VideoToolbox C
helper on macOS, OpenH264 downloads on Windows / Linux — are produced
automatically by `dart/hook/build.dart` during the build.

## What it verifies

- `dart/hook/build.dart` produces a loadable `.dylib` bundled into the app.
- Swift `FlutterTexture` plugin (`flutter/macos/Classes/WebdartcFlutterPlugin.swift`)
  receives frames over the method channel, converts I420 → NV12
  `CVPixelBuffer`, and hands them to Flutter's Metal compositor.
- End-to-end bidirectional video over real DTLS/SRTP/ICE with `sent`
  and `recv` counters both advancing.
- macOS sandbox entitlements permit WebSocket + UDP
  (`com.apple.security.network.client` / `network.server`).
