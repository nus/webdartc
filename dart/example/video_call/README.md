# video_call sample

Browser ↔ Dart WebRTC video call. The Dart `sender` pushes a fake video
stream (white text showing the current ms on a grey background); the browser
displays it in the "remote" tile. In `--bidir` mode the browser's own camera
is also sent back and decoded by the Dart side.

The browser page lays out two tiles side-by-side:

| Tile | Source |
|------|--------|
| `local`  | The browser's own camera stream (only populated with `?bidir=1`). |
| `remote` | Video received from the Dart `sender`. |

## Prerequisites

- Dart SDK 3.11+
- For **VP8**: `libvpx` (Linux: `apt install libvpx-dev`, macOS: `brew install libvpx`)
- For **H.264**: `libopenh264` (Linux: `apt install libopenh264-dev`,
  macOS: `brew install openh264` — not needed on macOS if you only use
  VideoToolbox, which is auto-selected for `--codec=h264`)

## Run

Terminal 1 — signaling + static HTTP server:

    dart run example/video_call/bin/server.dart --port=8080

Terminal 2 — open the browser (receive-only):

    http://127.0.0.1:8080/

For two-way video, open:

    http://127.0.0.1:8080/?bidir=1

(approve the camera permission prompt).

Terminal 3 — the Dart sender (creates the offer, starts pushing video):

    # VP8 (default, sendonly)
    dart run example/video_call/bin/sender.dart --port=8080 --codec=vp8
    # H.264 sendonly
    dart run example/video_call/bin/sender.dart --port=8080 --codec=h264
    # H.264 bidirectional — browser camera → Dart decoder (macOS uses VideoToolbox)
    dart run example/video_call/bin/sender.dart --port=8080 --codec=h264 --bidir

You should see the fake video (with rolling millisecond timestamps) in the
browser's `remote` tile within a few seconds. With `?bidir=1` + `--bidir` the
browser's own camera feed also shows in `local` and is decoded on the Dart
side (the sender logs `[sender] decoded #N`).

## Architecture

```
Dart sender (outgoing):
  FakeVideoSource → VideoEncoder (VP8 / libvpx or H.264 / VideoToolbox / OpenH264)
                  → Packetizer (RFC 7741 / RFC 6184 STAP-A + FU-A)
                  → RtpSender.sendRtp
                  → PeerConnection / SRTP / DTLS / ICE
                  → UDP → Browser → <video id="v">  (remote tile)

Browser (--bidir):
  getUserMedia → RTCPeerConnection.addTrack
              → UDP → Dart RtpReceiver
              → H264Depacketizer → VideoDecoder (VideoToolbox on macOS)
              → [sender] decoded #N
```
