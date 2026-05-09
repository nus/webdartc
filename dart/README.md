# webdartc

A WebRTC library written entirely in Dart by AI agents — RFC-compliant protocols with complete I/O isolation.

## Overview

webdartc implements the W3C WebRTC API in Dart as a set of pure state machines. All network I/O is isolated to a single controller module (`TransportController`), making the protocol logic deterministic and testable.

Supports data channels and media (audio/video) send/receive.

## Features

- **RFC-compliant protocols**: STUN (RFC 5389), ICE (RFC 8445), Trickle ICE (RFC 8840), DTLS 1.2 (RFC 6347), SRTP (RFC 3711), SCTP (RFC 4960), DCEP (RFC 8832), RTP/RTCP (RFC 3550), SDP (RFC 4566/8866), H.264 RTP (RFC 6184, STAP-A + FU-A), VP8 RTP (RFC 7741), Opus RTP (RFC 7587)
- **Pure state machines**: All protocol modules produce deterministic outputs from inputs — no hidden I/O
- **Platform-native crypto**: CommonCrypto + Security.framework on macOS, OpenSSL on Linux, via FFI
- **Data channels**: SCTP over DTLS with DCEP negotiation
- **Media**: Transceivers, RTP/RTCP, audio/video frame APIs (W3C Media Capture & Streams, WebCodecs)
- **Codecs**: VP8 via libvpx; H.264 via Apple VideoToolbox (hardware-accelerated on macOS/iOS) or OpenH264 (software, other platforms); Opus via vendored libopus (statically linked, no system install needed).

## Requirements

- Dart SDK >= 3.11.0, < 4.0.0
- CMake (used by the build hook to compile the vendored libopus)
- macOS (Xcode for VideoToolbox / CoreMedia / CoreVideo) or Linux (`clang libssl-dev libvpx-dev libopenh264-dev`)
- The `dart/third_party/opus/` submodule must be checked out (`git clone --recurse-submodules` or `git submodule update --init --recursive`).

## Installation

```yaml
dependencies:
  webdartc:
    git: https://github.com/nus/webdartc.git
```

```bash
dart pub get
```

## Quick start

```dart
import 'package:webdartc/webdartc.dart';

final pc = PeerConnection(configuration: PeerConnectionConfiguration());

// Create and set an offer
final offer = await pc.createOffer();
await pc.setLocalDescription(offer);

// Exchange offer/answer via your signaling server, then:
await pc.setRemoteDescription(remoteAnswer);

// Data channel
final dc = pc.createDataChannel('chat');
dc.onMessage.listen((msg) => print('Received: $msg'));
dc.send('hello');
```

## Architecture

```
PeerConnection (W3C API)
       │
TransportController  ← only module using dart:io
       │
 ┌─────┴──────────────────────────────────┐
 ICE   DTLS   SRTP   SCTP   RTP/RTCP   SDP
 │      │
STUN   Crypto (CommonCrypto / OpenSSL via FFI)
```

Each protocol module follows the same pattern:

- **Input**: `processInput(Uint8List packet, remoteIp, remotePort) → ProcessResult`
- **Timers**: `handleTimeout(TimerToken) → ProcessResult`
- **Output**: `List<OutputPacket>` + optional next `Timeout`

## Project structure

```
hook/
└── build.dart                 # Dart build hook: VideoToolbox C helper (Apple) + bundled libopus (macOS/Linux)
src/
├── wvt_callback.c             # VT encoder/decoder callback + CFRetain+queue bridge
├── wvt_callback.h
├── webdartc_opus.c            # libopus wrapper (only `webdartc_opus_*` exported)
└── webdartc_opus.h
third_party/
└── opus/                      # libopus submodule (statically linked, hidden symbols)

lib/
├── webdartc.dart              # Public API exports
├── peer_connection/           # W3C PeerConnection, DataChannel, events
├── transport/                 # TransportController (sole dart:io user)
├── ice/, dtls/, srtp/, sctp/, stun/, rtp/, sdp/
├── crypto/                    # Platform-specific crypto backends (FFI)
├── media/                     # MediaStream, tracks, frames, FakeVideoSource
├── codec/
│   ├── codec_registry.dart
│   ├── video_codec.dart       # W3C VideoEncoder / VideoDecoder
│   ├── audio_codec.dart       # W3C AudioEncoder / AudioDecoder
│   ├── vp8/                   # libvpx FFI encoder
│   ├── opus/                  # libopus FFI encoder/decoder (bundled)
│   └── h264/
│       ├── h264_encoder_backend.dart          # OpenH264 (SW)
│       ├── videotoolbox/                      # @Native bindings to the C helper
│       ├── videotoolbox_encoder_backend.dart  # VT encoder (macOS/iOS)
│       └── videotoolbox_decoder_backend.dart  # VT decoder (macOS/iOS)
└── core/                      # State machine base, Result<T,E>, types

test/
├── crypto/, stun/, ice/, dtls/, srtp/, sctp/, rtp/, sdp/, codec/
├── fuzz/                      # Fuzzing tests
└── e2e/                       # Browser E2E (Chrome / Firefox)

example/
├── ice_gather.dart            # ICE candidate gathering
├── opus_codec.dart            # Opus encode/decode round-trip + SNR check
├── audio_send/                # Browser ↔ Dart audio call (Opus)
├── reflect/                   # Audio/video reflection server + browser client
└── video_call/                # Browser ↔ Dart video call (VP8 / H.264, sendonly or bidir)
```

## Running tests

```bash
# Unit tests
dart test

# End-to-end tests (requires Chrome)
dart test test/e2e/

# Verify network I/O isolation (should produce no output)
grep -rn "RawDatagramSocket\|RawSocket" \
  lib/crypto/ lib/media/ lib/codec/ lib/core/ lib/peer_connection/
```

## Examples

```bash
# ICE candidate gathering with Google STUN server
dart run example/ice_gather.dart stun:stun.l.google.com:19302

# Audio/video reflection server
dart run example/reflect/server.dart --port=8080
# Open http://localhost:8080 in Chrome

# Video call — Dart sender → browser receiver (sendonly)
dart run example/video_call/bin/server.dart --port=8080 &
dart run example/video_call/bin/sender.dart --port=8080 --codec=h264
# Open http://localhost:8080 in Chrome

# Bidirectional: browser fake camera → Dart VideoToolbox decoder (macOS)
dart run example/video_call/bin/sender.dart --port=8080 --codec=h264 --bidir
# Open http://localhost:8080/?bidir=1 in Chrome
```

## Codec backends

| Codec | Encoder | Decoder | Source |
|-------|---------|---------|--------|
| H.264 (macOS/iOS) | VideoToolbox (HW) | VideoToolbox (HW) | `dart/hook/build.dart` auto-compiles a C helper |
| H.264 (Linux/Windows) | OpenH264 (SW) | — (roadmap) | `libopenh264-dev` |
| VP8 | libvpx (SW) | — (roadmap) | `libvpx-dev` |
| Opus (macOS/Linux) | libopus (SW) | libopus (SW) | `dart/third_party/opus/` submodule, statically linked |

On macOS, `dart test` triggers `hook/build.dart` which compiles `src/wvt_callback.c` into a bundled dynamic library. The shim retains `CMSampleBuffer`s before the VT callback returns and pushes them onto a thread-safe queue that the Dart side drains (a problem Dart FFI's async `NativeCallable.listener` cannot solve alone).

On macOS and Linux the same hook also configures CMake, builds libopus from `third_party/opus/` as a static archive (`libopus.a`), and links it into a single `webdartc_codecs` shared library alongside `src/webdartc_opus.c` (a thin wrapper that re-exports a small subset of the libopus API). Every libopus symbol is hidden by `-fvisibility=hidden` plus `-DOPUS_EXPORT=` (which neutralizes libopus's own `visibility("default")` attribute) — only `webdartc_opus_*` is visible from outside, so the bundled copy can't collide with another libopus loaded into the same process.

## Crypto backends

| Primitive | macOS | Linux |
|-----------|-------|-------|
| AES-128-CM (SRTP) | CommonCrypto | OpenSSL |
| AES-GCM | CommonCrypto | OpenSSL |
| ECDH P-256 | Security.framework | OpenSSL |
| ECDSA P-256 | Security.framework | OpenSSL |
| HMAC-SHA1/SHA-256 | package:crypto | package:crypto |
| HKDF | CommonCrypto | Manual |
| CSPRNG | CCRandomGenerateBytes | Random.secure() |
