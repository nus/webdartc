# media sample

Browser ↔ Dart WebRTC media sample with three roles:

- **`signaling.dart`** — HTTP + WebSocket signaling relay. Also serves the
  browser client (`web/index.html`) so the demo runs from one process tree.
- **`sender.dart`** — Dart peer that pushes a fake video stream (white text
  showing the current ms on a grey background). `--bidir` also decodes the
  browser's camera on the Dart side.
- **`echo.dart`** — Dart peer that reflects every received RTP packet back
  via the matching sender; the browser sees its own camera echoed.

The browser page (`web/index.html`) is the answerer for either Dart peer.
It lays out two tiles side-by-side:

| Tile | Source |
|------|--------|
| `local`  | The browser's own camera stream (only populated with `?bidir=1`). |
| `remote` | Video received from the Dart peer (`sender` fake video, or `echo`'s reflection). |

## Prerequisites

- Dart SDK 3.11+
- For **H.264**: `libopenh264` (Linux: `apt install libopenh264-dev`,
  macOS: `brew install openh264` — not needed on macOS if you only use
  VideoToolbox, which is auto-selected for `--codec=h264`)

VP8 has no system dependency — `libvpx` is vendored under
`dart/third_party/libvpx/` and built statically by `dart/hook/build.dart`
into a wrapper dylib with hidden symbols.

## Run

Terminal 1 — signaling + static HTTP server:

    dart run example/media/bin/signaling.dart --port=8080

### sender mode — Dart pushes fake video to the browser

Terminal 2 — open the browser (receive-only):

    http://127.0.0.1:8080/

For two-way video, open:

    http://127.0.0.1:8080/?bidir=1

(approve the camera permission prompt).

Terminal 3 — the Dart sender (creates the offer, starts pushing video):

    # VP8 (default, sendonly)
    dart run example/media/bin/sender.dart --port=8080 --codec=vp8
    # H.264 sendonly
    dart run example/media/bin/sender.dart --port=8080 --codec=h264
    # H.264 bidirectional — browser camera → Dart decoder (macOS uses VideoToolbox)
    dart run example/media/bin/sender.dart --port=8080 --codec=h264 --bidir

You should see the fake video (with rolling millisecond timestamps) in the
browser's `remote` tile within a few seconds. With `?bidir=1` + `--bidir` the
browser's own camera feed also shows in `local` and is decoded on the Dart
side (the sender logs `[sender] decoded #N`).

### echo mode — browser sees its own camera reflected by Dart

Terminal 2 — open the browser in bidir (the echo peer has no source media
of its own):

    http://127.0.0.1:8080/?bidir=1

Terminal 3 — the Dart echo peer:

    dart run example/media/bin/echo.dart --port=8080

The `remote` tile shows what the browser is sending, after a round-trip
through the Dart peer's RTP forwarder.

## Architecture

```
sender mode (Dart → browser, optional bidir return):
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

echo mode (browser → Dart → browser):
  Browser camera → UDP → Dart packetReceiver
                → packetSender (same kind, matching transceiver)
                → UDP → Browser <video id="v">
  (no encoder / decoder on the Dart side; packets are forwarded as-is.)
```
