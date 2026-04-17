# video_call sample

Dart → Browser one-way video call (VP8 or H.264). The Dart sender generates
fake video frames (white text showing the current ms on a grey background)
and streams them over WebRTC to a browser receiver.

## Prerequisites

- Dart SDK 3.11+
- For **VP8**: `libvpx` (Linux: `apt install libvpx-dev`, macOS: `brew install libvpx`)
- For **H.264**: `libopenh264` (Linux: `apt install libopenh264-dev`,
  macOS: `brew install openh264`)

## Run

Terminal 1 — signaling + static HTTP server:

    dart run example/video_call/bin/server.dart --port=8080

Terminal 2 — open the browser:

    http://127.0.0.1:8080/

The browser page will connect over WebSocket and wait.

Terminal 3 — the sender (creates the offer, starts pushing video):

    # VP8 (default)
    dart run example/video_call/bin/sender.dart --port=8080 --codec=vp8
    # H.264 via OpenH264
    dart run example/video_call/bin/sender.dart --port=8080 --codec=h264

You should see the fake video (with rolling millisecond timestamps) in the
browser's `<video>` element within a few seconds.

## Architecture

```
FakeVideoSource → VideoEncoder (VP8/libvpx or H.264/OpenH264 via FFI)
               → Packetizer (RFC 7741 / RFC 6184)
               → RtpSender.sendRtp
               → PeerConnection / SRTP / DTLS / ICE
               → UDP → Browser → <video>
```
