# media sample

Browser ↔ Dart WebRTC media sample.

Three Dart binaries under `bin/`, each playing a different role:

- **`sender.dart`** (HTTP + WS + Dart peer) — self-contained. Serves
  `web/index.html` on `/`, accepts a WebSocket upgrade, then pushes a
  FakeVideoSource stream (white text on grey background) to whichever
  browser opens the page. `--bidir` also subscribes to the browser's
  camera and decodes it on the Dart side.
- **`echo.dart`** (HTTP + WS + Dart peer) — self-contained. Same shape
  as `sender.dart`, but with no source media of its own — it forwards
  every received RTP packet back via the matching sender, so the
  browser sees its own camera reflected.
- **`signaling.dart`** (HTTP + WS relay) — *not* a peer. Used only when
  you need to pair two clients that both already are peers (e.g. the
  `flutter/example/` app talking to a browser). Hands JSON messages
  between any two connected WebSocket clients.

`web/index.html` is the browser side for all three; it is the
*answerer* in the call (the Dart peer is the offerer).

## Prerequisites

- Dart SDK 3.11+
- For **H.264**: `libopenh264` (Linux: `apt install libopenh264-dev`,
  macOS: `brew install openh264` — not needed on macOS if you only use
  VideoToolbox, which is auto-selected for `--codec=h264`)

VP8 has no system dependency — `libvpx` is vendored under
`dart/third_party/libvpx/` and built statically by `dart/hook/build.dart`
into a wrapper dylib with hidden symbols.

## Run — `sender` (Dart → browser, optional bidir return)

One terminal:

    # VP8 sendonly (default)
    dart run example/media/bin/sender.dart --port=8080 --codec=vp8

    # H.264 sendonly
    dart run example/media/bin/sender.dart --port=8080 --codec=h264

    # H.264 bidirectional — browser camera → Dart VT decoder (macOS)
    dart run example/media/bin/sender.dart --port=8080 --codec=h264 --bidir

Then open `http://127.0.0.1:8080/` (or `…/?bidir=1` for the matching
bidir case) in Chrome.

You should see the fake video (rolling millisecond timestamps) in the
browser's `remote` tile within a few seconds. With `?bidir=1 + --bidir`
the browser's own camera also shows in `local` and is decoded on the
Dart side (the sender logs `[sender] decoded #N`).

## Run — `echo` (browser camera reflected back via Dart)

One terminal:

    dart run example/media/bin/echo.dart --port=8080

Open `http://127.0.0.1:8080/?bidir=1` in Chrome (echo needs a
browser-sourced track to reflect). The `remote` tile shows the same
camera feed after a round-trip through the Dart peer's RTP forwarder.

## Run — `signaling` (for Flutter ↔ browser)

`flutter/example/` uses this. Three terminals:

    # 1. signaling relay + HTML
    cd dart && dart run example/media/bin/signaling.dart --port=8080
    # 2. http://127.0.0.1:8080/?bidir=1 in Chrome
    # 3. cd flutter/example && WEBDARTC_PORT=8080 flutter run -d macos

`signaling.dart` blindly forwards every JSON message between any two
connected WebSocket clients (no message-type knowledge); both peers
implement the WebRTC offer/answer/candidate dance themselves.

## Architecture

```
sender (Dart → browser, optional bidir return):
  FakeVideoSource → VideoEncoder (VP8 / libvpx or H.264 / VideoToolbox / OpenH264)
                  → Packetizer (RFC 7741 / RFC 6184 STAP-A + FU-A)
                  → RtpSender.sendRtp
                  → PeerConnection / SRTP / DTLS / ICE
                  → UDP → Browser → <video id="v">  (remote tile)

  Browser (--bidir):
    getUserMedia → RTCPeerConnection.addTrack
                → UDP → Dart RtpReceiver
                → Depacketizer → VideoDecoder (VideoToolbox on macOS)
                → [sender] decoded #N

echo (browser → Dart → browser):
  Browser camera → UDP → Dart packetReceiver
                → packetSender (same kind, matching transceiver)
                → UDP → Browser <video id="v">
  (no encoder / decoder on the Dart side; packets are forwarded as-is.)
```
