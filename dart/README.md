# webdartc

A WebRTC library written entirely in Dart — RFC-compliant protocols.

## Overview

webdartc implements the W3C WebRTC API as a set of protocol state machines that
turn inputs into outputs deterministically, which keeps the protocol logic
testable and packet-level behaviour reproducible.

Data channels and media (audio + video, send + receive) are both supported.

## Features

- **RFC-compliant protocols** — STUN (RFC 5389/8489), ICE (RFC 8445), Trickle
  ICE (RFC 8840), ICE consent freshness (RFC 7675), TURN (RFC 5766/8656, with
  UDP / TCP / TLS transports), DTLS 1.2 (RFC 6347), SRTP (RFC 3711), SCTP
  (RFC 4960), DCEP (RFC 8832), RTP/RTCP (RFC 3550), SDP (RFC 4566/8866), and the
  RTP payload formats for H.264 (RFC 6184, STAP-A + FU-A), VP8 (RFC 7741), VP9,
  and Opus (RFC 7587).
- **Pure state machines** — protocol modules produce deterministic outputs from
  inputs.
- **W3C surface** — `PeerConnection`, `DataChannel`, transceivers, and a
  `Webdartc` factory that owns a shared `SettingEngine` + `MediaEngine`. Public
  types drop the `RTC` prefix (`PeerConnection`, not `RTCPeerConnection`).
- **Platform-native crypto** via FFI — CommonCrypto + Security.framework on
  macOS, CNG (`bcrypt.dll`) on Windows, and BoringSSL (built via vcpkg,
  statically linked into the bundled `webdartc_crypto` wrapper) on Linux +
  Android.
- **Codecs** — VP8 / VP9 via libvpx (Android: MediaCodec), H.264 via Apple
  VideoToolbox (hardware-accelerated on macOS), Android MediaCodec
  (`AMediaCodec` via FFI), or Cisco-prebuilt OpenH264 (Linux + Windows), Opus
  via libopus (Android: MediaCodec). The libvpx + libopus submodules are still
  cross-compiled with the NDK for Android (bundled load-check). See
  [Codec backends](#codec-backends) for the per-OS codec source split (vcpkg on
  macOS / Windows, submodules elsewhere).

## Requirements

- Dart SDK `>= 3.11.0 < 4.0.0`.
- **macOS** — Xcode (VideoToolbox / CoreMedia / CoreVideo). libvpx + libopus are
  source-built via vcpkg, which the build hook clones + bootstraps itself (or
  honours `VCPKG_ROOT`) and which brings its own CMake; no submodules needed.
- **Linux** — `cmake clang nasm pkg-config` (build libopus, assemble libvpx's
  x86_64 SIMD; pkg-config for vcpkg's BoringSSL port). OpenH264 is
  auto-downloaded; codecs come from the submodules; BoringSSL is source-built
  via vcpkg (the build hook clones + bootstraps vcpkg itself, or honours
  `VCPKG_ROOT`). Submodules required.
- **Windows** — MSVC (Visual Studio "Desktop development with C++", already
  required by `flutter build windows`). The VP8 / VP9 / Opus wrapper DLLs are
  source-built from libvpx / libopus via vcpkg (auto-cloned + bootstrapped by
  the build hook, or `VCPKG_ROOT`); the Cisco OpenH264 binary is downloaded and
  CNG provides crypto. No submodules needed.
- **Android** — built through Flutter (`flutter test integration_test`, not
  `dart test`); needs the Android SDK + NDK + CMake + pkg-config. The build
  hook cross-compiles libvpx + libopus (codecs) with the NDK and source-builds
  BoringSSL (crypto) via vcpkg for each ABI (`ANDROID_NDK_HOME`). H.264 binds
  the system MediaCodec (`AMediaCodec`) via FFI and needs no build step.

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

// Offer / answer (exchange the SDP via your own signaling channel).
final offer = await pc.createOffer();
await pc.setLocalDescription(offer);
await pc.setRemoteDescription(remoteAnswer);

// Data channel.
final dc = pc.createDataChannel('chat');
dc.onMessage.listen((msg) => print('received: $msg'));
dc.send('hello');
```

Receiving media follows the W3C path — `onTrack` hands you a `MediaStreamTrack`
that already decodes. The bundled codec backends (VP8 / VP9 / H.264 / Opus) are
auto-registered, and subscribing to the track lazily starts an internal
jitter-buffer → depacketize → decode pipeline:

```dart
pc.onTrack.listen((event) {
  final track = event.track;            // non-null when the codec is supported
  if (track == null) return;            // else use event.receiver.onRtp (raw RTP)
  if (track.kind == 'video') {
    track.onVideoFrame.listen((frame) { /* render */ frame.close(); });
  } else {
    track.onAudioData.listen((audio) { /* play */ });
  }
});
```

For raw RTP (relays, SFU forwarding, custom codecs) use `event.receiver.onRtp`,
which always emits packets regardless of codec registration. To manage the
backends yourself, pass `autoRegisterCodecs: false` to `PeerConnection` /
`Webdartc` and register a subset.

For configured ICE servers, codec preferences, or port ranges, build through the
`Webdartc` factory:

```dart
final webrtc = Webdartc(
  settingEngine: SettingEngine(iceServers: [/* STUN / TURN */]),
  mediaEngine: MediaEngine(),            // VP8 + VP9 + H.264 + Opus by default
);
final pc = webrtc.createPeerConnection();
```

## Architecture

```
        Webdartc factory  (SettingEngine + MediaEngine)
               │
        PeerConnection  (W3C API: DataChannel, transceivers, stats)
               │
        TransportController        ← UDP send / receive
               │
 ┌──────┬──────┼──────┬──────┬──────┬──────┐
 ICE   TURN   DTLS   SRTP   SCTP  RTP/RTCP  SDP
 │             │
STUN          Crypto  (CommonCrypto / BoringSSL / CNG via FFI)
```

Every protocol module follows one shape:

- **Input** — `processInput(Uint8List packet, remoteIp, remotePort) → ProcessResult`
- **Timers** — `handleTimeout(TimerToken) → ProcessResult`
- **Output** — `ProcessResult` carries `List<OutputPacket>` + an optional next `Timeout`

Methods return `Result<T, ProtocolError>` (sealed `ParseError` / `StateError` /
`CryptoError` / `InternalError`) rather than throwing.

## Project structure

```
lib/
├── webdartc.dart              # public API exports
├── api/                       # Webdartc factory, SettingEngine, MediaEngine, stats
├── peer_connection/           # W3C PeerConnection, DataChannel, events
├── transport/                 # TransportController — UDP send / receive
├── ice/, turn/, dtls/, srtp/, sctp/, stun/, rtp/, sdp/
├── crypto/                    # platform crypto backends (FFI)
├── media/                     # MediaStream, tracks, frames, FakeVideoSource
│                              #   receiver_track + receive_pipeline (decode path)
├── codec/
│   ├── codec_registry.dart    # + default_codecs.dart (registerDefaultCodecs)
│   ├── video_codec.dart       # W3C VideoEncoder / VideoDecoder
│   ├── audio_codec.dart       # W3C AudioEncoder / AudioDecoder
│   ├── vp8/, vp9/             # libvpx FFI (vcpkg macOS/Windows, submodule Linux/Android)
│   ├── opus/                  # libopus FFI (same split as vp8/vp9)
│   └── h264/                  # OpenH264 (Linux/Windows) + VideoToolbox (macOS) backends
└── core/                      # state machine base, Result<T,E>, shared types

hook/build.dart               # native-asset build hook (codecs + VideoToolbox shim)
src/                          # C wrappers: wvt_callback, webdartc_opus, webdartc_vp8/vp9
third_party/                  # libopus + libvpx submodules (static, hidden symbols)

test/
├── crypto/, stun/, ice/, dtls/, srtp/, sctp/, rtp/, sdp/, codec/
├── fuzz/                      # fuzz tests
└── e2e/                       # browser e2e (Chrome / Firefox)

example/
├── ice_gather.dart            # ICE candidate gathering
├── opus_codec.dart            # Opus encode/decode round-trip + SNR check
├── get_user_media_macos.dart  # open camera/mic via AVFoundation (macOS)
├── audio_renderer_macos.dart  # speaker playback via AudioQueue (macOS)
├── audio_send/                # Dart → browser audio (Opus)
├── audio_receive/             # browser → Dart audio
├── video_sender/              # Dart → browser video (VP8 / H.264 fake source)
├── video_receiver/            # browser → Dart video (onTrack → onVideoFrame)
├── video_echo/                # browser → Dart → browser (RTP packet forward)
├── getusermedia_call/         # real camera + mic → browser (macOS, audio + video)
├── signaling/                 # HTTP + WS relay (OpenAyame, for the Flutter demo)
└── serve.dart                 # shared static-file serving for the demos above
```

## Tests

```bash
dart test                       # unit tests (runs the build hook)
dart test test/e2e/             # browser e2e (Chrome auto-downloaded)
dart test test/ice/ice_test.dart   # a single file
```

E2E tests are tagged `e2e` and need Chrome or Firefox with WebDriver; helpers
live in `test/e2e/`. Fuzz tests are in `test/fuzz/`.

## Examples

Each `example/<name>/server.dart` is a self-contained `dart run` entrypoint that
serves its own browser page and acts as the Dart peer.

```bash
# ICE candidate gathering against a public STUN server
dart run example/ice_gather.dart stun:stun.l.google.com:19302

# Dart → browser fake video (open http://localhost:8080 in Chrome)
dart run example/video_sender/server.dart --port=8080 --codec=h264

# browser camera → Dart decoder (macOS VideoToolbox for H.264)
dart run example/video_receiver/server.dart --port=8080 --codec=h264

# browser camera echoed back through a Dart RTP forwarder
dart run example/video_echo/server.dart --port=8080
```

## Codec backends

Every backend is software except VideoToolbox on macOS and MediaCodec on
Android, which use the OS-provided codec (hardware-accelerated where the device
offers it).

| Codec | macOS | Linux | Windows | Android |
|-------|-------|-------|---------|---------|
| H.264 | VideoToolbox (HW); `hook/build.dart` compiles `src/wvt_callback.c` | OpenH264, pinned download from `ciscobinary.openh264.org` | OpenH264, same Cisco prebuilt path | MediaCodec (NDK `AMediaCodec` via FFI); no build step |
| VP8   | libvpx via vcpkg, statically linked | libvpx submodule, source-built + statically linked | `webdartc_vp8.dll` wrapper from libvpx via vcpkg + MSVC | libvpx submodule, NDK cross-compiled per ABI |
| VP9   | same as VP8 (shares the libvpx archive) | same as VP8 | `webdartc_vp9.dll` (same archive as vp8) | same as VP8 (shares the libvpx archive) |
| Opus  | libopus via vcpkg, statically linked | libopus submodule, source-built + statically linked | `webdartc_opus.dll` wrapper from libopus via vcpkg + MSVC | libopus submodule, NDK cross-compiled per ABI |

[`hook/build.dart`](hook/build.dart) runs on every platform and selects the path:

- **VideoToolbox shim (macOS)** — compiles `src/wvt_callback.c` into a bundled
  dylib. The shim retains each `CMSampleBuffer` before the VT callback returns
  and queues it for the Dart side to drain — something `NativeCallable.listener`
  can't do alone.
- **OpenH264 (Linux + Windows)** — downloads the Cisco prebuilt binary
  (`_openH264Version` / `_openH264Sha256` pin version + hash) and registers it as
  a `DynamicLoadingBundled` asset. See <https://www.openh264.org/> for upstream
  terms.
- **MediaCodec (Android)** — no native asset; `lib/codec/h264/mediacodec/`
  binds the system `libmediandk.so` (`AMediaCodec`) via pure-Dart FFI, using the
  synchronous buffer API so it needs no C shim (unlike the VideoToolbox path).
  MediaCodec is the OS-provided, patent-licensed codec — the Android analogue of
  VideoToolbox. Regenerate the FFI bindings with
  `dart run tool/gen_mediacodec_bindings.dart` (needs the NDK's libclang).
- **libopus / libvpx source build (macOS / Windows, via vcpkg)** — `vcpkg
  install` (ports pinned by `tool/lib{opus,vpx}_vcpkg/vcpkg.json`) produces
  `libopus.a` / `libvpx.a`; on macOS the build hook links them directly into the
  bundled dylibs, on Windows `tool/build_lib{opus,vpx}_wrappers.dart` compiles
  the `webdartc_*` DLLs with MSVC. vcpkg is auto-cloned + bootstrapped if not on
  `VCPKG_ROOT` / PATH; Windows additionally needs MSVC (already a `flutter build
  windows` prerequisite). The libvpx archive is built once per triplet and
  shared by VP8 + VP9.
- **libopus / libvpx source build (Linux / Android, via submodules)** — CMake /
  libvpx's `configure` build the bundled `third_party/{opus,libvpx}` submodules
  (Android cross-compiles through the NDK toolchain). Same `webdartc_{opus,vp8,vp9}.c`
  wrappers, exporting only `webdartc_*`.

Every codec symbol is hidden (`-fvisibility=hidden` on macOS / Linux;
`__declspec(dllexport)` for `webdartc_*` only on Windows) so the bundled copies
can't collide with another libopus / libvpx in the same process. For libopus we
additionally pre-define `OPUS_EXPORT=` to neutralize its own
`visibility("default")`.

## Crypto backends

| Primitive | macOS | Linux | Windows | Android |
|-----------|-------|-------|---------|---------|
| AES-128-CM / AES-GCM (SRTP) | CommonCrypto | BoringSSL | CNG (BCrypt) | BoringSSL |
| ECDH P-256 | Security.framework | BoringSSL | CNG (BCrypt) | BoringSSL |
| ECDSA P-256 | Security.framework | BoringSSL | CNG (BCrypt) | BoringSSL |
| HMAC-SHA1 / SHA-256 | package:crypto | package:crypto | package:crypto | package:crypto |
| CSPRNG | `Random.secure()` | `Random.secure()` | `Random.secure()` | `Random.secure()` |

Linux + Android share one backend: BoringSSL is source-built via vcpkg and
statically linked into the bundled `webdartc_crypto` wrapper, which exports only
the `wd_*` passthroughs that `lib/crypto/openssl.dart` binds via `@Native`
(BoringSSL's own symbols stay hidden — the same shape as the codec wrappers).
ChaCha20-Poly1305 and the self-signed DTLS certificate use the pure-Dart
implementations (BoringSSL exposes ChaCha only via EVP_AEAD, not EVP_CIPHER).

## Third-party licenses

webdartc bundles or downloads libvpx, libopus, and OpenH264 — their licenses
apply to anything you redistribute. Full text is in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). On Linux the build hook also
drops a `NOTICE.txt` next to the downloaded OpenH264 binary so the governing text
travels with it.
