# webdartc

A WebRTC library written entirely in Dart by AI agents — RFC-compliant protocols with complete I/O isolation.

## Overview

webdartc implements the W3C WebRTC API in Dart as a set of pure state machines. All network I/O is isolated to a single controller module (`TransportController`), making the protocol logic deterministic and testable.

Supports data channels and media (audio/video) send/receive.

## Features

- **RFC-compliant protocols**: STUN (RFC 5389), ICE (RFC 8445), Trickle ICE (RFC 8840), DTLS 1.2 (RFC 6347), SRTP (RFC 3711), SCTP (RFC 4960), DCEP (RFC 8832), RTP/RTCP (RFC 3550), SDP (RFC 4566/8866), H.264 RTP (RFC 6184, STAP-A + FU-A), VP8 RTP (RFC 7741), Opus RTP (RFC 7587)
- **Pure state machines**: All protocol modules produce deterministic outputs from inputs — no hidden I/O
- **Platform-native crypto**: CommonCrypto + Security.framework on macOS, OpenSSL on Linux, CNG (`bcrypt.dll`) on Windows, via FFI
- **Data channels**: SCTP over DTLS with DCEP negotiation
- **Media**: Transceivers, RTP/RTCP, audio/video frame APIs (W3C Media Capture & Streams, WebCodecs)
- **Codecs**: VP8 + VP9 via libvpx; H.264 via Apple VideoToolbox (hardware-accelerated on macOS) or Cisco-prebuilt OpenH264 (software, Linux + Windows); Opus via libopus. See [Codec backends](#codec-backends) below for the build-hook details and the per-OS source-vs-prebuilt split.

## Requirements

- Dart SDK >= 3.11.0, < 4.0.0
- macOS (Xcode for VideoToolbox / CoreMedia / CoreVideo + CMake to build the bundled libopus / libvpx), Linux (`cmake clang yasm libssl-dev` — yasm is required by libvpx's x86_64 SIMD assembly; OpenH264 is auto-downloaded by the build hook on first run), or Windows (no additional tools for the default prebuilt path — `dart pub get` downloads the wrapper DLLs + the Cisco OpenH264 binary; the MSVC source-build opt-in needs Visual Studio + vcpkg).
- On macOS and Linux the `dart/third_party/opus/` and `dart/third_party/libvpx/` submodules must be checked out (`git clone --recurse-submodules` or `git submodule update --init --recursive`). The Windows default path does not need the submodules — they are only required when opting in to the source build.

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
└── build.dart                 # Dart build hook: VT C helper (Apple) +
                                #   bundled libopus + libvpx (macOS/Linux)
src/
├── webdartc_export.h          # Single source for the WEBDARTC_API macro
├── wvt_callback.{h,c}         # VT encoder/decoder callback + CFRetain+queue bridge
├── webdartc_opus.{h,c}        # libopus wrapper (`webdartc_opus_*` exported)
├── webdartc_vp8.{h,c}         # libvpx wrapper, VP8 enc + dec (`webdartc_vp8_*`)
└── webdartc_vp9.{h,c}         # libvpx wrapper, VP9 enc + dec (`webdartc_vp9_*`)
third_party/
├── opus/                      # libopus submodule (statically linked, hidden symbols)
└── libvpx/                    # libvpx submodule (statically linked, hidden symbols;
                                #   shared archive across webdartc_vp8 + webdartc_vp9)

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
│   ├── vp8/                   # libvpx FFI encoder + decoder (source-built on
│   │                          # macOS / Linux, prebuilt DLL on Windows)
│   ├── vp9/                   # libvpx FFI encoder + decoder (same as vp8)
│   ├── opus/                  # libopus FFI encoder + decoder (source-built on
│   │                          # macOS / Linux, prebuilt DLL on Windows)
│   └── h264/
│       ├── _openh264.dart                     # @Native bindings to bundled OpenH264 dylib / DLL
│       ├── openh264_bindings.g.dart           # ffigen structs/enums/vtables
│       ├── h264_encoder_backend.dart          # OpenH264 SW encoder (Linux + Windows)
│       ├── h264_decoder_backend.dart          # OpenH264 SW decoder (Linux + Windows)
│       ├── videotoolbox/                      # @Native bindings to the C helper
│       ├── videotoolbox_encoder_backend.dart  # VT encoder (macOS)
│       └── videotoolbox_decoder_backend.dart  # VT decoder (macOS)
└── core/                      # State machine base, Result<T,E>, types

test/
├── crypto/, stun/, ice/, dtls/, srtp/, sctp/, rtp/, sdp/, codec/
├── fuzz/                      # Fuzzing tests
└── e2e/                       # Browser E2E (Chrome / Firefox)

example/
├── ice_gather.dart            # ICE candidate gathering
├── opus_codec.dart            # Opus encode/decode round-trip + SNR check
├── audio_send/                # Browser ↔ Dart audio call (Opus)
└── media/                     # Browser ↔ Dart video sample
                               #   signaling + browser client + Dart sender
                               #   (fake video, VP8/H.264, sendonly or bidir)
                               #   + Dart echo peer (reflects browser camera)
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

# Media sample — sender (Dart → browser receiver, sendonly)
dart run example/media/bin/sender.dart --port=8080 --codec=h264
# Open http://localhost:8080 in Chrome

# bidir: browser fake camera → Dart VideoToolbox decoder (macOS)
dart run example/media/bin/sender.dart --port=8080 --codec=h264 --bidir
# Open http://localhost:8080/?bidir=1 in Chrome

# echo: browser camera reflected back via the Dart peer
dart run example/media/bin/echo.dart --port=8080
# Open http://localhost:8080/?bidir=1 in Chrome
```

## Codec backends

All backends are software (SW) except VideoToolbox on macOS, which is hardware-accelerated.

| Codec | macOS | Linux | Windows |
|-------|-------|-------|---------|
| H.264 | VideoToolbox (HW) — `hook/build.dart` auto-compiles `src/wvt_callback.c` | OpenH264, downloaded from `ciscobinary.openh264.org` (version + SHA-256 pinned) | OpenH264, same Cisco prebuilt path as Linux |
| VP8   | libvpx submodule, source-built and statically linked | (same as macOS) | `webdartc_vp8.dll` (CI-built wrapper, libvpx statically linked); source-build opt-in |
| VP9   | (same as VP8) | (same as VP8) | `webdartc_vp9.dll` (same archive as `vp8.dll`); source-build opt-in |
| Opus  | libopus submodule, source-built and statically linked | (same as macOS) | `webdartc_opus.dll` (CI-built wrapper, libopus statically linked); source-build opt-in |

`hook/build.dart` runs on every supported platform and selects the right path:

- **VideoToolbox shim (macOS)** — compiles `src/wvt_callback.c` into a bundled dynamic library. The shim retains `CMSampleBuffer`s before the VT callback returns and pushes them onto a thread-safe queue the Dart side drains (a problem Dart FFI's async `NativeCallable.listener` cannot solve alone).
- **OpenH264 (Linux + Windows)** — downloads the Cisco prebuilt binary from `ciscobinary.openh264.org` (see `_openH264Version` / `_openH264Sha256` in `hook/build.dart`) into the shared build cache and registers it as a `DynamicLoadingBundled` code asset under `package:webdartc/codec/h264/_openh264.dart`. See https://www.openh264.org/ for the upstream project's distribution terms.
- **libopus / libvpx source build (macOS / Linux)** — CMake / libvpx's own `configure` produce `libopus.a` / `libvpx.a`, then `webdartc_{opus,vp8,vp9}.c` are linked in to produce `libwebdartc_codecs.{dylib,so}` (exports `webdartc_opus_*`) and `libwebdartc_vp{8,9}.{dylib,so}` (exports `webdartc_vp{8,9}_*`). The libvpx archive is built once per arch and reused for VP8 + VP9.
- **libopus / libvpx prebuilt download (Windows)** — wrapper DLLs are pre-built by the matching `.github/workflows/build-lib{opus,vpx}-prebuilt.yaml` workflow on each release of the `webdartc-libvpx-prebuilt-*` / `webdartc-libopus-prebuilt-*` GitHub release tags. The consumer machine does not need MSVC / vcpkg. Opt in to a local MSVC + vcpkg source build by setting `hooks.user_defines.webdartc.libvpx_source_build` / `libopus_source_build` to true in the workspace-root `pubspec.yaml` — the hook then runs `dart/tool/build_libvpx_wrappers.dart` / `build_libopus_wrappers.dart` instead of the download.

Every codec symbol is hidden via `-fvisibility=hidden` on macOS / Linux, and on Windows by exporting only `webdartc_*` symbols with `__declspec(dllexport)`. The bundled copies can't collide with another libopus / libvpx loaded into the same process; for libopus we additionally pre-define `OPUS_EXPORT=` to neutralize its own `visibility("default")` attribute.

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

## Third-party licenses

`webdartc` bundles or downloads third-party codec libraries — their licenses apply to any binary you redistribute. Full text for each (libvpx, libopus, OpenH264) lives in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). On Linux, `dart/hook/build.dart` also drops a `NOTICE.txt` alongside the downloaded OpenH264 dylib (`.dart_tool/hooks_runner/shared/webdartc/openh264-*/NOTICE.txt`) so the governing text travels with the binary.
