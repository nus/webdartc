# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

This is a monorepo with two packages:

- `webdartc/` — pure-Dart WebRTC library (this document's focus). Run commands from inside this directory.
- `webdartc_flutter/` — Flutter integration (rendering Widget, codecs, camera/mic capture, speaker playback). Run Flutter commands from inside this directory.

All paths and commands below are relative to `webdartc/` unless noted.

## Project

webdartc is a WebRTC library written entirely in Dart. It implements the W3C WebRTC API as pure state machines with all network I/O isolated to a single module (`TransportController`). Supports data channels and media (audio/video) send/receive.

- Dart SDK >= 3.11.0
- Platform-native crypto via FFI: CommonCrypto + Security.framework on macOS, OpenSSL on Linux
- Only dependency: `package:crypto` (for HMAC-SHA1/SHA-256)

## Commands

```bash
# Install dependencies
dart pub get

# Run all unit tests
dart test

# Run a single test file
dart test test/crypto/aes_cm_test.dart

# Run e2e tests (requires Chrome or Firefox)
dart test test/e2e/

# Run analysis
dart analyze

# Run an example
dart run example/ice_gather.dart stun:stun.l.google.com:19302
dart run example/reflect/server.dart --port=8080
```

## Architecture

All protocol modules are pure state machines (`ProtocolStateMachine` in `lib/core/state_machine.dart`) with no I/O:
- **Input**: `processInput(Uint8List packet, remoteIp, remotePort) -> Result<ProcessResult, ProtocolError>`
- **Timers**: `handleTimeout(TimerToken) -> Result<ProcessResult, ProtocolError>`
- **Output**: `ProcessResult` contains `List<OutputPacket>` + optional `Timeout`

`TransportController` (`lib/transport/`) is the **only** module that uses `dart:io` for UDP. All other modules must never import `dart:io` or perform network operations directly.

```
PeerConnection (W3C API, no RTC prefix)
       |
TransportController  <- only module using dart:io
       |
 ICE   DTLS   SRTP   SCTP   RTP/RTCP   SDP
 |      |
STUN   Crypto (CommonCrypto / OpenSSL via FFI)
```

## Key Conventions

- **No RTC prefix**: W3C types use short names (`PeerConnection`, `DataChannel`, not `RTCPeerConnection`)
- **Result type**: Protocol methods return `Result<T, ProtocolError>` (lib/core/result.dart), not exceptions
- **Sealed error types**: `ParseError`, `StateError`, `CryptoError`, `InternalError` (all extend `ProtocolError`)
- **Timer tokens**: Each protocol has its own `TimerToken` subclass (e.g., `IceTimerToken`, `DtlsRetransmitToken`, `SctpT3RtxToken`)
- **I/O isolation**: Verify with `grep -rn "RawDatagramSocket\|RawSocket" lib/crypto/ lib/media/ lib/codec/ lib/core/ lib/peer_connection/` (should produce no output)

## Analysis

Strict analysis is enabled: `strict-casts`, `strict-inference`, `strict-raw-types`. The analyzer excludes `example/`, `tool/`, and `test/e2e/`. Key lint rules: `avoid_dynamic_calls`, `avoid_print`, `unawaited_futures`.

## Testing

- E2e tests are tagged with `e2e` in `dart_test.yaml` and require Chrome or Firefox with WebDriver
- E2e helpers (signaling server, browser launchers, WebDriver session) are in `test/e2e/`
- Fuzz tests are in `test/fuzz/`

## Reference

The `webrtc-impl/` directory contains the implementation skill and RFC/W3C specification resources used to build this library. Consult `webrtc-impl/resources/` for protocol details, coding guidelines, and Chrome interop notes.
