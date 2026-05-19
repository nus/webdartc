# Backlog

Issues found during reviews, refactors, or other work that were intentionally
deferred because they were out of scope for the current change. New entries go
in the right section, with date, source, and an acceptance note. Drop entries
when shipped.

## Format

Each item:

```
### <one-line title>
- **Found:** YYYY-MM-DD, in <branch / PR / context>
- **Detail:** <what the issue is>
- **Why deferred:** <reason>
- **Acceptance:** <what done looks like>
```

---

## Codec / FFI

### Shared dynamic-library loader helper

- **Found:** 2026-05-04, in `opus-codec` /simplify
- **Detail:** `_openLibvpx()` ([dart/lib/codec/vp8/vp8_encoder_backend.dart](dart/lib/codec/vp8/vp8_encoder_backend.dart)),
  `_openLibOpenH264()` ([dart/lib/codec/h264/h264_encoder_backend.dart](dart/lib/codec/h264/h264_encoder_backend.dart)),
  `_open()` in [_libopus.dart](dart/lib/codec/opus/_libopus.dart), and `OpenSsl._loadLibcrypto()`
  ([dart/lib/crypto/openssl.dart](dart/lib/crypto/openssl.dart)) all implement the same
  `Platform.is{macOS,Windows,Linux}` candidate-loop pattern. Four copies of
  effectively identical code.
- **Why deferred:** Cross-cuts four modules; out of scope for the Opus branch.
- **Acceptance:** New `dart/lib/codec/native_loader.dart` (or a more general
  shared util) exposing `openNativeLibrary({macos, linux, windows, label})`.
  All four callers reduce to one-liners. Apple-framework absolute-path loaders
  in `crypto/macos_backend.dart` and `crypto/security_framework.dart` stay as
  they are.

### Project-wide codec name constants

- **Found:** 2026-05-04, in `opus-codec` /simplify
- **Detail:** Codec keys (`'vp8'`, `'h264'`, `'opus'`) are stringly-typed at
  every registration site, every `CodecRegistry.create*` call, and across all
  tests. Refactoring just one codec would be inconsistent with the others.
- **Why deferred:** Cross-codec change; not blocking shipping.
- **Acceptance:** Introduce `VideoCodecName` / `AudioCodecName` constant
  groups in `video_codec.dart` / `audio_codec.dart`. Update all backends and
  tests to reference them.

### Android codec backend (MediaCodec via JNI)

- **Found:** 2026-05-04, codec-status review
- **Detail:** Flutter Android cannot encode or decode video — no MediaCodec
  bridge exists.
- **Why deferred:** JNI integration is large; needs Flutter-side native
  plumbing.
- **Acceptance:** `MediaCodec`-backed encoder/decoder for H.264 (and ideally
  VP8) on Android, integrated through the Flutter plugin's native side.

### AV1 codec

- **Found:** 2026-05-04, codec-status review
- **Detail:** No AV1 backend; libaom / dav1d are not wired up. (VP9 has since
  landed under `dart/lib/codec/vp9/`.)
- **Why deferred:** Not required for the current target Chrome / Firefox
  interop story.
- **Acceptance:** AV1 encoder + decoder registered, basic round-trip test
  passes.

### Opus DTX / FEC support

- **Found:** 2026-05-04, in `opus-codec` /simplify
- **Detail:** Opus encoder runs without `OPUS_SET_DTX` / `OPUS_SET_INBAND_FEC`
  knobs and the decoder always passes `decode_fec=0`. Bandwidth and packet-loss
  resilience are sub-optimal.
- **Why deferred:** First-pass scope was limited to working encode/decode.
- **Acceptance:** Configurable DTX and in-band FEC in `AudioEncoderConfig`
  extension; decoder honors `decode_fec` when the upstream signals a missing
  prior packet. Tests cover both paths.

### Opus 8 / 16 / 24 kHz sample rates

- **Found:** 2026-05-04, in `opus-codec` /simplify
- **Detail:** All Opus encode/decode tests run at 48 kHz. Lower rates are
  accepted by the API but exercised by no test. (Mono / `channels: 1` is
  already tested at 48 kHz — see `dart/test/codec/opus_libopus_update_test.dart`.)
- **Why deferred:** WebRTC default is 48 kHz; lower-rate paths can wait
  until a caller needs them.
- **Acceptance:** Tests at 8 / 16 / 24 kHz encode/decode round-trip pass.

---

## Network / ICE

### `SettingEngine.udpPortRange` is not plumbed

- **Found:** 2026-05-04, post-multi-bind branch summary
- **Detail:** [dart/lib/api/setting_engine.dart](dart/lib/api/setting_engine.dart)
  declares `udpPortRange: (int, int)?` as a public-API knob, but
  `TransportController.start()` always binds via `bind(addr, 0)` (random
  ephemeral). The field is dead state.
- **Why deferred:** Wasn't blocking the multi-bind work.
- **Acceptance:** `start()` selects a port from the configured range (random
  walk or sequential probe); falls back to `0` only when the range is null.
  Test covers a small explicit range.

### Multi-host srflx gathering

- **Found:** 2026-05-04, post-multi-bind branch summary
- **Detail:** With per-interface UDP bind in place, host candidates gather
  correctly across all bound IPs. Server-reflexive (srflx) gathering still
  only fires from the first host — peers behind NAT see fewer candidates than
  they should.
- **Why deferred:** Multi-bind branch focused on host candidates; srflx is its
  own change.
- **Acceptance:** STUN binding requests fan out from each bound socket; one
  srflx candidate per (host, STUN-server) pair.

### SDP builder assumes a single host

- **Found:** 2026-05-04, post-multi-bind branch summary
- **Detail:** SDP builder takes `localIp:` / `localPort:` (single value) — the
  multi-bind work surfaced multiple host IPs that all need to appear in the
  emitted SDP as separate `a=candidate` lines.
- **Why deferred:** API change; affects callers.
- **Acceptance:** Builder accepts a list of `(IpAddress, int port)` host
  bindings (or pulls them from `TransportController` directly); generated SDP
  contains one candidate per binding.

### Sealed `Destination` type for OutputPacket

- **Found:** 2026-05-04, multi-bind design discussion
- **Detail:** `OutputPacket` currently identifies its target with bare IP/port
  fields. Once TURN-UDP / TURN-TCP / TURN-TLS land, the destination
  abstraction needs to carry transport, allocation handle, and channel info —
  a sealed `Destination` hierarchy.
- **Why deferred:** Premature until at least one TURN transport is being
  implemented.
- **Acceptance:** `sealed class Destination` with subclasses for each TURN
  flavor and direct UDP. `TransportController` dispatches on the type.

---

## Housekeeping

### `example/reflect/` does not use the Webdartc factory

- **Found:** 2026-05-04, post-multi-bind branch summary
- **Detail:** The reflect example still constructs `PeerConnection(...)`
  directly instead of going through the new `Webdartc` factory + `SettingEngine`
  pattern.
- **Why deferred:** Intentionally skipped — example code, not library code.
- **Acceptance:** Either migrate the example to the factory pattern, or
  delete this entry as a permanent decision.
