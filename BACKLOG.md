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

### End-of-candidates is never signaled or processed

- **Found:** 2026-05-29, RFC/W3C divergence audit (webrtc-impl skill). **Unverified —
  confirm against the code before fixing.**
- **Detail:** RFC 8838 §8.2 / RFC 8840 §4.2.7. There is no
  `addIceCandidate(null)` / `a=end-of-candidates` handling. The controlled
  agent can't learn the remote trickle stream is finished, so it can't declare
  `failed` early — an agent waiting for candidates that never arrive hangs.
  Suspected sites: [dart/lib/peer_connection/peer_connection.dart](dart/lib/peer_connection/peer_connection.dart),
  [dart/lib/ice/state_machine.dart](dart/lib/ice/state_machine.dart).
- **Why deferred:** Out of scope for the audit pass; needs SDP-parser + ICE-FSM
  changes plus an E2E hang-recovery test.
- **Acceptance:** Parse `a=end-of-candidates`, expose an
  `endOfRemoteCandidates()` call, and let connectivity-check completion declare
  failure without waiting once end-of-candidates has been received.

### TURN IPv6 relay (REQUESTED-ADDRESS-FAMILY) not supported

- **Found:** 2026-05-29, RFC/W3C divergence audit (webrtc-impl skill). **Unverified.**
- **Detail:** RFC 6156 §4 (MUST per `rfc_specs.md`). `Allocate` is sent with
  only `REQUESTED-TRANSPORT`; `REQUESTED-ADDRESS-FAMILY` (0x0017) and
  `ADDITIONAL-ADDRESS-FAMILY` (0x8000) are neither defined in `attributes.dart`
  nor emitted, so an IPv6 relay can't be requested.
  [dart/lib/turn/state_machine.dart](dart/lib/turn/state_machine.dart).
- **Why deferred:** No IPv6 relay test target yet; the IPv4 path works.
- **Acceptance:** Add + parse/encode both attributes, expose an address-family
  knob on the allocation, and cover an IPv6 relay request in a test.

### TURN-over-TCP (RFC 6062) not implemented

- **Found:** 2026-05-29, RFC/W3C divergence audit (webrtc-impl skill). **Unverified.**
- **Detail:** RFC 6062 (MUST per `rfc_specs.md`). The Connect / ConnectionBind /
  ConnectionAttempt methods (0x000A/0x000B/0x000C), the `CONNECTION-ID`
  attribute, and the data-connection FSM are absent. Note: the existing
  `?transport=tcp` control-link support is the *client→server TCP control*
  channel, which is a different mechanism from RFC 6062 peer-data TCP.
- **Why deferred:** No caller needs TCP-relayed peer data yet.
- **Acceptance:** A Connect FSM managing the data-connection lifecycle, with an
  integration test against a TCP-relay-capable TURN server.

---

## DTLS / SRTP

> Entries below come from the 2026-05-29 RFC/W3C divergence audit (webrtc-impl
> skill, parallel sub-agents). They are **unverified leads** — re-read the cited
> code against the RFC section before acting; some may be false positives.

### ALPN `webrtc` extension never sent in the DTLS handshake

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 7301. The `alpn = 0x0010` constant exists
  ([dart/lib/dtls/v13/handshake.dart](dart/lib/dtls/v13/handshake.dart)) but no
  flight (1.2 or 1.3) emits an ALPN extension carrying `"webrtc"`. Chrome sends
  it; absence may degrade interop / future-proofing.
  [dart/lib/dtls/handshake.dart](dart/lib/dtls/handshake.dart).
- **Why deferred:** Audit pass only; needs a handshake-bytes test.
- **Acceptance:** Both ClientHello and ServerHello include an ALPN extension
  with the single protocol `"webrtc"`; verified against captured bytes.

### ClientHello offers only ECDHE-ECDSA, not ECDHE-RSA

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 7742 §6.1. ClientHello offers
  `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B) only;
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F) is missing, so a peer
  presenting an RSA cert in `a=fingerprint` would hit handshake_failure.
  [dart/lib/dtls/state_machine.dart](dart/lib/dtls/state_machine.dart),
  [dart/lib/dtls/cipher_suite.dart](dart/lib/dtls/cipher_suite.dart).
- **Why deferred:** webdartc itself uses ECDSA certs; only matters interop-ing
  with an RSA-cert peer.
- **Acceptance:** Add 0xC02F to the `CipherSuite` enum and offer both suites.

### `use_srtp` offers only one SRTP profile

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 5764 §4.1.1. `use_srtp` advertises only
  `SRTP_AES128_CM_HMAC_SHA1_80` (0x0001) even though the SRTP context supports
  0x0001/0x0002/0x0007/0x0008. Negotiation can't reach the other profiles.
  [dart/lib/dtls/handshake.dart](dart/lib/dtls/handshake.dart),
  [dart/lib/srtp/context.dart](dart/lib/srtp/context.dart).
- **Why deferred:** The 80-bit profile is the common case and works.
- **Acceptance:** Advertise the full set the SRTP layer supports; an SRTP-GCM
  interop path is exercised by a test.

---

## SCTP / Data Channel

> Same 2026-05-29 audit; **unverified leads.**

### Wrong PPID for empty DataChannel messages

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 8831 §8. `dcep.dart` appears to use `webrtcStringEmpty = 56`
  / `webrtcBinaryEmpty = 57`; the spec assigns **52 = DOMString Empty** and
  **54 = Binary Empty**. A wrong PPID makes Chrome reject empty messages.
  [dart/lib/sctp/dcep.dart](dart/lib/sctp/dcep.dart).
- **Why deferred:** Audit pass; trivial fix but needs an empty-message E2E.
- **Acceptance:** Constants corrected to 52 / 54; an empty `send('')` /
  `send(Uint8List(0))` round-trips against Chrome.

### DataChannel close doesn't send SCTP stream reset (RECONFIG)

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 6525 / RFC 8831 §6.7. `DataChannel.close()` flips local state
  only; no `OUTGOING_SSN_RESET_REQUEST` is sent, and the SCTP layer doesn't
  parse the `reconfig` chunk (declared but unhandled). Also the W3C `closing`
  state is effectively skipped (set + cleared in one tick; `onclosing` never
  fires).
  [dart/lib/sctp/state_machine.dart](dart/lib/sctp/state_machine.dart),
  [dart/lib/peer_connection/data_channel.dart](dart/lib/peer_connection/data_channel.dart).
- **Why deferred:** Needs RECONFIG send + parse + handler and an E2E close test.
- **Acceptance:** Close initiates a stream reset, awaits the peer's reset,
  fires `onclosing` then `onclose`; RECONFIG round-trips against Chrome.

---

## RTP / RTCP / SDP

> Same 2026-05-29 audit; **unverified leads.**

### Answer `a=setup` is hard-coded to `active`

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 5763 §5. The answer builder emits `a=setup:active`
  unconditionally. The answerer MUST pick `passive` when the offer is `active`,
  and `active` only when the offer is `actpass` / `passive`; otherwise both
  sides race to be DTLS client.
  [dart/lib/sdp/parser.dart](dart/lib/sdp/parser.dart).
- **Why deferred:** webdartc-as-offerer (the common e2e path) sends `actpass`,
  so the bug only bites when the remote offers `active`.
- **Acceptance:** Answer derives setup from the offer; an `a=setup:active`
  offer yields an `a=setup:passive` answer.

### H.264 FU-A can emit S=1 and E=1 in the same fragment

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 6184 §5.8. When a NAL is just over `maxPayloadSize`, a single
  FU-A is emitted with both Start and End bits set, which the RFC forbids;
  should fall back to a Single NAL Unit packet.
  [dart/lib/rtp/packetizer.dart](dart/lib/rtp/packetizer.dart).
- **Why deferred:** Edge case; only triggers at a specific NAL size.
- **Acceptance:** A single-fragment case emits a Single NAL Unit packet; an
  exactly-`maxPayloadSize+1` NAL decodes correctly in Chrome.

### FIR command sequence number hard-coded to 1

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 5104 §4.3.1. Every FIR uses seq number 1, so repeated FIRs are
  treated as duplicates and ignored by the receiver; should increment mod 256
  per target SSRC.
  [dart/lib/peer_connection/peer_connection.dart](dart/lib/peer_connection/peer_connection.dart).
- **Why deferred:** Keyframe-on-demand mostly relies on PLI today.
- **Acceptance:** Per-SSRC FIR counter incremented mod 256; a second FIR
  triggers a fresh keyframe.

### RTCP RR sent on a fixed 100 ms timer

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 3550 §6.2 / RFC 4585 §3.5. A fixed 100 ms RR interval ignores
  the RTCP bandwidth budget (≈5 % of session bandwidth); on an audio-only Opus
  session (~32 kbps) it consumes a large fraction of the link.
  [dart/lib/peer_connection/peer_connection.dart](dart/lib/peer_connection/peer_connection.dart).
- **Why deferred:** Works for the short-lived e2e tests; matters for real,
  bandwidth-constrained calls.
- **Acceptance:** Implement the RFC 3550 §6.3 timing algorithm with the AVPF
  `Tmin` reduction; honour `trr-int` when present.

### Generic NACK cannot be sent

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 4585 §6.2.1. `RtcpNack` decodes on receive but has no
  `build()`, so webdartc can't request retransmission.
  [dart/lib/rtp/packet.dart](dart/lib/rtp/packet.dart).
- **Why deferred:** Loss recovery via RTX isn't wired up yet.
- **Acceptance:** `RtcpNack.build()` produces a PT=205 FMT=1 packet with
  `(PID, BLP)` FCI entries; decoded correctly by Chrome.

---

## W3C API conformance

> Same 2026-05-29 audit; **unverified leads.** These track public-surface gaps
> against the W3C WebRTC / Media Capture / WebCodecs specs (the project's
> no-`RTC`-prefix convention is intentional and not a gap).

### PeerConnection: missing spec methods and accessors

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** W3C §4.3. Missing: `getReceivers()`, `getTransceivers()`,
  `removeTrack()`, `restartIce()`, `getConfiguration()`, `setConfiguration()`;
  the `currentLocalDescription` / `pendingLocalDescription` split (and remote
  counterparts); `iceGatheringState` + `onIceGatheringStateChange`;
  `onNegotiationNeeded`, `onIceCandidateError`. `addTransceiver` returns `void`
  rather than the created transceiver, and `PeerConnectionState` starts in
  `connecting`, skipping the spec `new`.
  [dart/lib/peer_connection/peer_connection.dart](dart/lib/peer_connection/peer_connection.dart),
  [dart/lib/peer_connection/events.dart](dart/lib/peer_connection/events.dart).
- **Why deferred:** Surface-area work; prioritise by what callers actually need.
- **Acceptance:** Each missing member added with spec semantics + tests; state
  enums match the W3C value sets.

### DataChannel: no flow-control surface

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** W3C §6.2. Missing `bufferedAmount`,
  `bufferedAmountLowThreshold`, `onBufferedAmountLow`, `binaryType`, and
  `onClosing`. Without `bufferedAmount` callers can't back-pressure large
  transfers.
  [dart/lib/peer_connection/data_channel.dart](dart/lib/peer_connection/data_channel.dart).
- **Why deferred:** Needs SCTP-ack accounting to drive `bufferedAmount`.
- **Acceptance:** `bufferedAmount` tracks queued bytes (decrement on SCTP ack),
  the threshold + low event fire, `binaryType` is honoured.

### RtpSender / RtpReceiver / RtpTransceiver surface is minimal

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** W3C §5. Sender has only `replaceTrack` (missing `getParameters`,
  `setParameters`, `getStats`, `transport`); receiver lacks
  `getContributingSources` / `getSynchronizationSources` / `getStats`; there is
  no public `RtpTransceiver` (only a private `_MediaTransceiver`) with `mid`,
  `direction`, `currentDirection`, `setDirection`, `stop`.
  [dart/lib/peer_connection/events.dart](dart/lib/peer_connection/events.dart).
- **Why deferred:** Surface-area work behind the negotiation core.
- **Acceptance:** At minimum `getParameters` / `setParameters` on the sender and
  a public `RtpTransceiver`; `RtpTransceiverDirection` enum introduced.

### MediaStreamTrack: missing settings/constraints surface

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** W3C Media Capture §4.3. Missing `getSettings()`,
  `getCapabilities()`, `getConstraints()`, `applyConstraints()`, `muted`,
  `onMute` / `onUnmute` / `onEnded`. `stop()` is fire-and-forget (no `onEnded`).
  [dart/lib/media/media_stream_track.dart](dart/lib/media/media_stream_track.dart).
- **Why deferred:** Capture-side feature work.
- **Acceptance:** `getSettings()` + `onEnded` at minimum; constraint methods as
  capture grows.

### getStats: missing `remote-outbound-rtp` and inbound-rtp fields

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** W3C §8. `remote-outbound-rtp` (emitted when the remote sends SR
  packets) is absent though `RtcpSenderReport` is already parsed.
  `InboundRtpStats` lacks spec-required `jitter`, `packetsLost`, `kind`,
  `codecId` (marked TODO).
  [dart/lib/api/stats.dart](dart/lib/api/stats.dart),
  [dart/lib/peer_connection/peer_connection.dart](dart/lib/peer_connection/peer_connection.dart).
- **Why deferred:** getStats already covers the common types; these fill gaps.
- **Acceptance:** `remote-outbound-rtp` emitted from received SRs; the inbound
  fields populated and asserted in `stats_test.dart`.

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

### STUN / TURN comments cite obsoleted RFCs

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** `stun/*` files reference RFC 5389 and `turn/*` files reference RFC
  5766 in doc comments, but `rfc_specs.md` mandates RFC 8489 (obsoletes 5389)
  and RFC 8656 (obsoletes 5766). Wire format is compatible; only the citations
  and some §-numbers (e.g. FINGERPRINT is §14.7 in 8489) are stale.
- **Why deferred:** Cosmetic; no behaviour change.
- **Acceptance:** Mechanical citation update across `dart/lib/stun/` and
  `dart/lib/turn/`.

### `Crc32c` class in `stun/` actually computes CRC-32

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** [dart/lib/stun/crc32c.dart](dart/lib/stun/crc32c.dart) is named
  `Crc32c` but uses the CRC-32 polynomial `0xEDB88320` — which is *correct* for
  STUN FINGERPRINT (RFC 8489 §14.7), but the name invites the exact CRC-32 vs
  CRC-32c mix-up `coding_guide.md` warns about. (The SCTP `crc32c.dart` is a
  separate, correct CRC-32c.)
- **Why deferred:** Pure rename; no behaviour change.
- **Acceptance:** Rename the class/file to `Crc32`; update the `stun/builder.dart`
  import.

### `Hkdf.prfSha256` is actually a TLS 1.2 PRF

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** [dart/lib/crypto/hkdf.dart](dart/lib/crypto/hkdf.dart) exposes
  `prfSha256` on the `Hkdf` class, but the body implements TLS 1.2 P_SHA256
  (RFC 5246 §5), not HKDF (RFC 5869). The math is correct; the name is
  misleading.
- **Why deferred:** Cosmetic; widely referenced, so renaming touches callers.
- **Acceptance:** Rename to reflect TLS-PRF, or split the PRF into its own
  helper; update call sites.
