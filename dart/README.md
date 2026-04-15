# webdartc

A WebRTC library written entirely in Dart by AI agents — RFC-compliant protocols with complete I/O isolation.

## Overview

webdartc implements the W3C WebRTC API in Dart as a set of pure state machines. All network I/O is isolated to a single controller module (`TransportController`), making the protocol logic deterministic and testable.

Supports data channels and media (audio/video) send/receive.

## Features

- **RFC-compliant protocols**: STUN (RFC 5389), ICE (RFC 8445), Trickle ICE (RFC 8840), DTLS 1.2 (RFC 6347), SRTP (RFC 3711), SCTP (RFC 4960), DCEP (RFC 8832), RTP/RTCP (RFC 3550), SDP (RFC 4566/8866)
- **Pure state machines**: All protocol modules produce deterministic outputs from inputs — no hidden I/O
- **Platform-native crypto**: CommonCrypto + Security.framework on macOS, OpenSSL on Linux, via FFI
- **Data channels**: SCTP over DTLS with DCEP negotiation
- **Media**: Transceivers, RTP/RTCP, audio/video frame APIs (W3C Media Capture & Streams, WebCodecs)

## Requirements

- Dart SDK >= 3.11.0, < 4.0.0
- macOS (CommonCrypto / Security.framework) or Linux (OpenSSL)

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
lib/
├── webdartc.dart              # Public API exports
├── peer_connection/           # W3C PeerConnection, DataChannel, events
├── transport/                 # TransportController (sole dart:io user)
├── protocol/
│   ├── ice/                   # ICE state machine & candidates
│   ├── dtls/                  # DTLS 1.2 handshake & records
│   ├── srtp/                  # SRTP encryption context
│   ├── sctp/                  # SCTP state machine & DCEP
│   ├── stun/                  # STUN messages, parser, builder
│   ├── rtp/                   # RTP/RTCP parsing & packetization
│   └── sdp/                   # SDP parser & session descriptions
├── crypto/                    # Platform-specific crypto backends (FFI)
├── media/                     # MediaStream, tracks, frames
├── codec/                     # Audio/video codec registry
└── core/                      # State machine base, Result<T,E>, types

test/
├── crypto/, stun/, ice/, dtls/, srtp/, sctp/, rtp/, sdp/
├── fuzz/                      # Fuzzing tests
└── e2e/                       # End-to-end tests with Chrome

example/
├── ice_gather.dart            # ICE candidate gathering
└── reflect/                   # Audio/video reflection server + browser client
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
```

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
