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
  they are. The platform-dispatch half of this shape already exists as
  `forPlatform` in [dart/lib/core/platform_dispatch.dart](dart/lib/core/platform_dispatch.dart)
  (landed with the 2026-07-04 crypto-factory dedup) — build the loader on top
  of or alongside it rather than adding a second dispatch helper.

### Android H.264 codec (MediaCodec via NDK FFI) — DONE (2026-06-27)

- **Found:** 2026-05-04, codec-status review. **Narrowed 2026-06-15:** VP8 / VP9 /
  Opus build + run on Android. **Shipped 2026-06-27** (`android-h264-mediacodec`).
- **Detail:** Android now has an H.264 backend built on the NDK `AMediaCodec`
  (MediaCodec) via **pure-Dart FFI — no JNI / Flutter-side native plumbing**.
  This uses the OS-provided patent-licensed codec, the Android analogue of
  VideoToolbox (OpenH264-from-source was avoided: Cisco's royalty grant only
  covers Cisco-distributed binaries, with no Android prebuilt).
  - Synchronous buffer API (dequeue/queueInputBuffer), so **no C shim** unlike
    the callback-based VideoToolbox helper; multistream works because each
    track gets its own `AMediaCodec`, all driven on the isolate thread.
    [dart/lib/codec/h264/mediacodec/mediacodec_helper.dart](dart/lib/codec/h264/mediacodec/mediacodec_helper.dart)
    + `mediacodec_{encoder,decoder}_backend.dart`; `registerH264Codec()` gains
    an `Platform.isAndroid` branch; the example negotiates H.264 everywhere.
  - Colour as packed I420 (encoder converts straight into the native input
    buffer as NV12, falling back to planar; decoder reads stride/slice-height).
    Key frames prepend the cached CODEC_CONFIG SPS/PPS.
  - `libmediandk.so` is loaded at runtime (no code asset / build-hook change);
    bindings generated from the NDK sysroot by
    [dart/tool/gen_mediacodec_bindings.dart](dart/tool/gen_mediacodec_bindings.dart)
    (resolves the NDK from env, token template — no committed `$HOME` path).
  - Tests: host colour-conversion unit tests + Android-gated roundtrip
    (key-frame/SPS prepend, PTS, non-trivial luma) and 3-stream multistream,
    run on-device via the integration_test aggregator. Verified bidirectional
    H.264 vs a Chrome peer on an arm64 emulator (API 35).
- **Not covered (follow-ups):** per-frame force-IDR (PLI-driven keyframe
  recovery relies on the I-frame interval); input stride/slice-height padding
  on HW encoders (v1 assumes width/height packing — fine on the emulator SW
  codec); vendor-proprietary tiled decoder outputs are dropped. HW MediaCodec
  accel for VP8/VP9 could ride the same FFI approach.

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

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Verified 2026-06; very low
  value — likely won't ship.**
- **Detail:** The DTLS 1.2 ClientHello
  ([dart/lib/dtls/handshake.dart](dart/lib/dtls/handshake.dart) `_buildClientHelloBody`)
  emits only extended_master_secret / supported_groups / signature_algorithms /
  use_srtp — no ALPN (0x0010). The `alpn = 0x0010` constant
  ([dart/lib/dtls/v13/handshake.dart](dart/lib/dtls/v13/handshake.dart)) is
  unused.
- **Why deferred — no practical payoff:**
  - **RFC 8833 makes ALPN optional**, not mandatory: a peer that omits it is
    treated as having negotiated `webrtc`. RFC 8827 (WebRTC security) doesn't
    mention ALPN at all.
  - **libwebrtc doesn't use ALPN for the P2P DTLS connection.** Its
    `rtc_base/openssl_stream_adapter.cc` configures no `SSL_set_alpn_protos`
    (so Chrome **doesn't send** ALPN — the audit's "Chrome sends it" was wrong)
    and no `SSL_CTX_set_alpn_select_cb` (so it **doesn't validate** a peer's
    ALPN; a non-`webrtc` or absent value is ignored, never rejected).
  - Our e2e completes DTLS with Chrome today with no ALPN on either side.
  - So implementing it buys zero interop benefit; the only effect would be
    future-proofing against a hypothetical ALPN-enforcing middlebox. Sending
    it (ClientHello only, no server-side enforcement) is harmless if we ever
    want the conformance checkbox.
- **Acceptance (if ever done):** ClientHello carries an ALPN extension with the
  single protocol `webrtc`; the server side does NOT enforce ALPN (must keep
  accepting peers — like Chrome — that send none). Verified against captured
  handshake bytes.

### No ECDHE-RSA support (RSA-cert peers can't complete DTLS)

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Verified 2026-05-30.**
- **Detail:** RFC 7742 §6.1 wants both ECDSA- and RSA-cert support. The
  `CipherSuite` enum ([dart/lib/dtls/cipher_suite.dart](dart/lib/dtls/cipher_suite.dart))
  only has the two ECDHE-**ECDSA** suites (0xC02B, 0xC009), and the client
  ServerKeyExchange handler hardcodes `EcdsaVerify.verifyP256Sha256`
  ([dart/lib/dtls/state_machine.dart](dart/lib/dtls/state_machine.dart) ~L665).
  So a peer that presents an RSA certificate (e.g. an app that called
  `RTCPeerConnection.generateCertificate({name:'RSASSA-PKCS1-v1_5'})`)
  fails the handshake. **Not just a missing cipher-suite constant** — making
  it work needs real new crypto:
  1. add `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F) to the enum +
     ClientHello;
  2. branch ServerKeyExchange / CertificateVerify on the negotiated suite
     (or the signature-algorithm field) to pick ECDSA vs RSA;
  3. an **RSA-PKCS1/PSS signature-verify primitive across all three crypto
     backends** (macOS CommonCrypto/Security.framework, Linux OpenSSL,
     Windows CNG — today only ECDSA verify is wired);
  4. RSA public-key extraction in the cert parser (only EC keys are
     extracted today).
- **Why deferred:** Low payoff for the cost. webdartc always presents an
  ECDSA self-signed cert, so it only ever needs ECDHE-RSA as the *client*
  talking to an *RSA-cert server* — and Chrome/Firefox default to ECDSA P-256
  for WebRTC, so the common case already works. RSA certs only appear when a
  peer explicitly opts into them.
- **Acceptance:** webdartc-as-client completes a DTLS handshake against a
  peer presenting an RSA certificate (cipher suite 0xC02F), with the
  ServerKeyExchange RSA signature verified on all three platforms; the
  ECDSA path is unaffected.

### `use_srtp` offers only one SRTP profile

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 5764 §4.1.1. `use_srtp` advertises only
  `SRTP_AES128_CM_HMAC_SHA1_80` (0x0001) even though the SRTP context supports
  0x0001/0x0002/0x0007/0x0008. Negotiation can't reach the other profiles.
  [dart/lib/dtls/handshake.dart](dart/lib/dtls/handshake.dart),
  [dart/lib/srtp/context.dart](dart/lib/srtp/context.dart).
- **Why deferred:** The 80-bit profile is the common case and works.
- **Acceptance:** Advertise the full set the SRTP layer supports; an SRTP-GCM
  interop path is exercised by a test. While here, settle the server-side
  preference-order divergence now centralized (2026-07-04) as
  `SrtpProfileNegotiation.v12Preference` (AES-CM first) vs `v13Preference`
  (GCM first) in [dart/lib/dtls/srtp_profiles.dart](dart/lib/dtls/srtp_profiles.dart)
  — unifying the order changes negotiation results, so it was deliberately
  left as-is by the profile-table dedup.

---

## SCTP / Data Channel

### Gate non-DATA chunk handlers on association state

- **Found:** 2026-06, /simplify of the DCEP-open fix.
- **Detail:** RFC 4960 §5. `_handleData` now discards chunks received before
  the association is `established`, but the sibling handlers `_handleSack`,
  `_handleHeartbeat`, and `_handleReconfig`
  ([dart/lib/sctp/state_machine.dart](dart/lib/sctp/state_machine.dart)) still
  run in any state — e.g. a SACK in `cookieWait`/`cookieEchoed` would mutate
  `_remoteRwnd` / drain the retransmit queue before establishment. pion gates
  all of these on state. Latent (a conformant peer won't send them
  pre-establishment, and the VTag check rejects most stray chunks), so it's
  hardening against malformed/misordered peers, not a live bug.
- **Why deferred:** Out of scope for the open-race fix; each handler needs its
  own state consideration (SACK vs HEARTBEAT vs RE-CONFIG differ).
- **Acceptance:** Reply/state-mutating chunk handlers no-op (or respond per
  RFC) when received before `established`; a fuzz/misordered-peer test covers it.

---

## RTP / RTCP / SDP

> Same 2026-05-29 audit; **unverified leads.**

### FIR command sequence number hard-coded to 1

- **Found:** 2026-05-29, RFC/W3C divergence audit. **Unverified.**
- **Detail:** RFC 5104 §4.3.1. Every FIR uses seq number 1, so repeated FIRs are
  treated as duplicates and ignored by the receiver; should increment mod 256
  per target SSRC.
  [dart/lib/peer_connection/peer_connection.dart](dart/lib/peer_connection/peer_connection.dart).
- **Why deferred:** Keyframe-on-demand mostly relies on PLI today.
- **Acceptance:** Per-SSRC FIR counter incremented mod 256; a second FIR
  triggers a fresh keyframe. While here, extract the inline raw-byte FIR
  builder in `_sendRtcpRR` (~L1714) into an `RtcpFir` class with the same
  `build()` contract as `RtcpPli` (2026-07-03 refactoring audit).

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

### PeerConnection: remaining spec methods and accessors — DONE (2026-06)

- **Found:** 2026-05-29, RFC/W3C divergence audit. Fully shipped 2026-06.
- **Detail:** W3C §4.3. Shipped across several PRs: `getReceivers()` /
  `getTransceivers()` and `addTransceiver` returning the transceiver (#42);
  `getConfiguration()`, `iceGatheringState` + `onIceGatheringStateChange`;
  `restartIce()` (ICE-agent restart + answerer auto-restart on a changed-ufrag
  offer; DTLS/SCTP persist). Final batch:
  - `removeTrack()` — detaches the track and downgrades the transceiver
    (`sendrecv`→`recvonly`, `sendonly`→`inactive`); fires negotiationneeded.
  - `setConfiguration()` — `configuration` is now a mutable holder; rejects
    `bundlePolicy`/`rtcpMuxPolicy` changes (W3C `InvalidModificationError`).
  - `currentLocalDescription` / `pendingLocalDescription` split (and remote) —
    maintained alongside the internal `localDescription`/`remoteDescription`
    in set{Local,Remote}Description.
  - `onNegotiationNeeded` (microtask-coalesced flag, cleared on local apply),
    `onIceCandidateError` (STUN gather timeout → 701, or server error code).
  - `PeerConnectionState` now starts in `newState` (the spec `new`; `new` is a
    Dart keyword so the value mirrors `IceConnectionState.iceNew`).
  [dart/lib/peer_connection/peer_connection.dart](dart/lib/peer_connection/peer_connection.dart),
  [dart/lib/peer_connection/events.dart](dart/lib/peer_connection/events.dart).

### DataChannel: `binaryType` + internal send flow control

- **Found:** 2026-05-29, RFC/W3C divergence audit. bufferedAmount shipped 2026-06.
- **Detail:** W3C §6.2. `bufferedAmount` / `bufferedAmountLowThreshold` /
  `onBufferedAmountLow` and `onClosing` are now implemented
  ([dart/lib/peer_connection/data_channel.dart](dart/lib/peer_connection/data_channel.dart));
  `bufferedAmount` tracks un-acked application bytes, decremented from SCTP
  SACKs. Still open:
  - **`binaryType`** — a browser Blob/ArrayBuffer distinction with no Dart
    analog (incoming messages are always `Uint8List`); would be an inert
    property, so left out deliberately.
  - **Internal SCTP send flow control.** `bufferedAmount` gives *app-level*
    back-pressure (a cooperating caller paces on it), but `sendData` still
    blasts every chunk to the transport immediately, ignoring the remote
    `a_rwnd` (read from SACK at
    [state_machine.dart](dart/lib/sctp/state_machine.dart) but never
    enforced) and any congestion window — so a non-cooperating sender can
    still overrun a slow receiver.
- **Acceptance:** `sendData` holds chunks when the peer's rwnd (and ideally a
  congestion window) is exhausted and drains on SACK; covered by a loss/slow-
  receiver test.

### RtpSender / RtpReceiver surface is minimal

- **Found:** 2026-05-29, RFC/W3C divergence audit. RtpTransceiver shipped 2026-06;
  sender `getParameters`/`setParameters` shipped 2026-06.
- **Detail:** W3C §5. The public `RtpTransceiver` (with `mid`, `direction`,
  `currentDirection`, `setDirection`, `stop`, `sender`, `receiver`) and the
  `RtpTransceiverDirection` enum now exist, and `PeerConnection` exposes
  `getTransceivers()` / `getReceivers()` (`addTransceiver` returns the
  transceiver). `RtpSender.getParameters()` / `setParameters()` are now
  implemented with a single `RtpEncodingParameters` (no simulcast): `active`
  gates `sendRtp` (an inactive encoding emits no media); `maxBitrate` /
  `maxFramerate` are stored advisories for the encoder backend; the
  `transactionId` is single-use and validated per spec.
  Still missing: sender `getStats`; receiver `getContributingSources` /
  `getSynchronizationSources` / `getStats`.
  [dart/lib/peer_connection/events.dart](dart/lib/peer_connection/events.dart).
- **Why deferred:** Surface-area work behind the negotiation core. The receiver
  source methods need CSRC/SSRC arrival tracking on the receive path.
- **Acceptance:** ~~`getParameters` / `setParameters` on the sender (at least
  active + bitrate)~~ (done), and CSRC tracking behind the receiver source
  methods.

### MediaStreamTrack: constraints surface

- **Found:** 2026-05-29, RFC/W3C divergence audit. Partially shipped 2026-06.
- **Detail:** W3C Media Capture §4.3. `getSettings()`, `muted`,
  `onMute`/`onUnmute`/`onEnded` are now implemented on
  [dart/lib/media/media_stream_track.dart](dart/lib/media/media_stream_track.dart)
  (capture tracks populate `MediaTrackSettings`; `stop()` fires `onEnded`).
  Still missing: `getCapabilities()`, `getConstraints()`,
  `applyConstraints()`.
- **Why deferred:** Constraint application means reconfiguring the capture
  source mid-stream (re-opening the camera/mic at a new resolution / rate) —
  a much larger, capture-backend-specific change than the read-only settings
  surface already shipped.
- **Acceptance:** `applyConstraints()` reconfigures the live source (at least
  resolution + frame rate for video), `getCapabilities()` reports the
  device's supported ranges.

### getStats: missing `remote-outbound-rtp` and inbound-rtp fields — ALREADY DONE

- **Found:** 2026-05-29, RFC/W3C divergence audit (claim **Unverified**).
  Verified 2026-06: the audit claim was stale — both items were already
  implemented and tested (likely landed with the 2026-06 getStats/media work),
  the BACKLOG entry just wasn't updated.
- **Detail:** W3C §8. Contrary to the audit:
  - `remote-outbound-rtp` *is* emitted: received SRs are captured in
    `_onRtcpReceived` (srPacketCount/srOctetCount/srNtp*/reportsReceived) and
    surfaced as `remote-outbound-rtp-<ssrc>`, paired with the inbound entry.
  - `InboundRtpStats` *has* `kind`, `packetsReceived`, `bytesReceived`,
    `packetsLost` (cumulativeLost), `jitter` (jitterSeconds), `codecId` — all
    populated with real values in `getStats()`.
  [dart/lib/api/stats.dart](dart/lib/api/stats.dart),
  [dart/lib/peer_connection/peer_connection.dart](dart/lib/peer_connection/peer_connection.dart).
- **Acceptance (met):** `remote-outbound-rtp` and the inbound fields are
  asserted on a loopback flow in
  [dart/test/api/stats_test.dart](dart/test/api/stats_test.dart) (remote-outbound
  kind/localId/reportsReceived/packetsSent/remoteTimestamp; inbound
  kind/packetsLost/jitter/codecId).

---

## Android

### BoringSSL prebuilt distribution (avoid building via vcpkg at build time)

- **Found:** 2026-06-17, BoringSSL crypto migration.
- **Detail:** Linux + Android crypto source-builds BoringSSL via vcpkg inside
  the build hook ([dart/hook/build.dart](dart/hook/build.dart) `_buildBoringSslCrypto`),
  which clones + bootstraps vcpkg and compiles BoringSSL the first time (minutes;
  cached under `outputDirectoryShared`). This is the explicitly-chosen model, but
  it puts vcpkg + a full BoringSSL build on the default Linux/Android build path.
- **Why deferred:** Functional and cached; the cost is build-time only.
- **Acceptance:** Optionally mirror the Windows codec model — a
  `build-boringssl-prebuilt.yaml` workflow that vcpkg-builds `libcrypto.a` per
  triplet and publishes SHA-256-pinned zips; the hook downloads them by default
  (`_bundleLibvpxPrebuilt` pattern), keeping vcpkg as an opt-in source build.

### Android platform support (crypto + codecs + Flutter render) — DONE (2026-06-15; crypto reworked 2026-06-17)

- **Found:** 2026-06-13 Android-support investigation; landed 2026-06-15.
- **Detail:** First Android milestone — "browser → Android receive + Flutter
  render". Verified on an Android emulator (API 35, arm64) via a throwaway
  Flutter app (crypto 10/10, codec round-trips 3/3, DTLS data channel A→B,
  render plugin + visual frame display):
  - **Crypto** — initially via the platform JCA (`package:jni`), but that made
    `webdartc` require the Flutter SDK and broke the pure-Dart `dart` CI (PR #54).
    **Reworked 2026-06-17** to BoringSSL: [boringssl_backend.dart](dart/lib/crypto/boringssl_backend.dart)
    (shared by Linux + Android) over [openssl.dart](dart/lib/crypto/openssl.dart)'s
    `@Native` bindings to the `webdartc_crypto` wrapper, which statically links
    vcpkg-built `libcrypto.a` ([dart/src/webdartc_crypto.c](dart/src/webdartc_crypto.c),
    [hook/build.dart](dart/hook/build.dart) `_buildBoringSslCrypto`). `jca.dart`,
    `android_backend.dart`, and the `jni` dependency were deleted; webdartc is
    pure-Dart again. ChaCha20-Poly1305 + the cert DER stay pure-Dart.
  - **Codecs** — `OS.android` branch in
    [dart/hook/build.dart](dart/hook/build.dart): libopus via the NDK
    `android.toolchain.cmake`, libvpx via its `*-android-gcc` targets driven by
    NDK clang env vars. VP8/VP9/Opus only (H.264 deferred — see above). Gotcha:
    the wrapper `.so` must link `-lm` (Android keeps libm separate).
  - **Render** — [flutter/android/](flutter/android/) Kotlin `FlutterPlugin`
    behind the shared `webdartc_flutter/render` MethodChannel: SurfaceTexture +
    CPU I420→ARGB (BT.601 full-range). `android:` platform added to
    [flutter/pubspec.yaml](flutter/pubspec.yaml); `flutter/example/android/`
    runner added; the example negotiates VP8/Opus on Android.
- **Notes / non-Android-specific:** the webdartc↔webdartc loopback B→A echo on a
  single channel times out on the host too (pre-existing SCTP/data-channel
  behaviour, unrelated to Android).

### Android render: zero-copy via MediaCodec output Surface (drop CPU convert)

- **Found:** 2026-06-15, Android render plugin first pass.
- **Detail:** The Android renderer does a per-frame CPU I420→ARGB conversion
  (Kotlin integer math) into a `Bitmap`, then `Surface.lockCanvas` /
  `drawBitmap` / `unlockCanvasAndPost`
  ([flutter/android/.../WebdartcFlutterPlugin.kt](flutter/android/src/main/kotlin/dev/webdartc/webdartc_flutter/WebdartcFlutterPlugin.kt)).
  At high resolution / frame rate this is CPU-heavy (convert + setPixels +
  canvas copy each frame). macOS hands Flutter an NV12 `CVPixelBuffer` and lets
  the Metal compositor do YUV→RGB; Android has no equivalent zero-copy path yet.
- **Primary direction — MediaCodec → Surface, zero-copy.** The biggest win is
  to *not convert on the CPU at all*: feed the Flutter texture's `Surface`
  (`SurfaceProducer`) directly as a hardware `MediaCodec` decoder's output
  surface, so decoded frames never round-trip to Dart as I420. The Android
  H.264/MediaCodec backend now exists (see "Android H.264 codec" above —
  DONE 2026-06-27), **but it decodes to a ByteBuffer (CPU I420), not a
  Surface**, so this still needs the decoder reworked to `AMediaCodec_configure`
  with an output `ANativeWindow` from the Flutter `SurfaceProducer`.
- **Secondary — GPU convert for software-decoded I420.** When frames still come
  from the software libvpx/libopus path as raw I420, do the YUV→RGB on the GPU
  instead of the CPU. **Use GLES, not Vulkan:** for a single video quad the two
  perform identically, and GLES is far cheaper to implement. Vulkan's only edge
  is skipping one GL↔Vulkan interop copy against Impeller's Vulkan backend —
  marginal gain, large cost (`VK_KHR_sampler_ycbcr_conversion` immutable
  samplers, AHardwareBuffer import, uneven emulator/driver support) — so not
  worth it here.
- **Why deferred:** Plan was "CPU color conversion first; optimise once it
  renders." Correctness shipped; this is the optimisation, and the zero-copy
  path is gated on the MediaCodec backend.
- **Acceptance:** Decoded frames reach the Flutter texture without a CPU
  I420→ARGB convert — via the MediaCodec output Surface for the HW path, and/or
  a GLES YUV→RGB shader for the software path. Measure the per-frame CPU drop at
  720p30 vs. the current Canvas path.

### Android end-to-end (browser interop) + real device + CI

- **Found:** 2026-06-15, Android-support milestone.
- **Done so far:** On-device `integration_test` suite under
  [flutter/example/integration_test/](flutter/example/integration_test/):
  - `dart_suite_test.dart` runs the Dart package's **own** platform-relevant
    tests on-device by relative-importing `dart/test/**` (crypto ×66, codec
    VP8/VP9/Opus ×32, peer_connection ICE/DTLS/SCTP loopback ×41) and calling
    each `main()` under the integration_test binding — single source of truth
    with host `dart test`, no duplicated assertions. (`package:test` and
    `flutter_test` share one `test_api` declarer; `test` is a dev_dep of the
    example.)
  - `render_test.dart` covers the render plugin (create/render/dispose) — the
    only piece with no `dart/test` equivalent.
  - Green on the Android emulator (API 35 arm64): 140/140. On macOS each file
    passes individually (`flutter test integration_test/<file> -d macos`);
    running the whole dir at once on macOS hits a desktop multi-file app-relaunch
    flake (not a test failure).
- **Manually verified 2026-06-27:** a full **browser↔Android** call — bidirectional
  H.264 against a Chrome fake-media peer over the local Ayame signaling server,
  the emulator (API 35 arm64) decoding Chrome's stream and rendering it (done
  while shipping the MediaCodec H.264 backend). Still **not automated**: this was
  a hand-driven run, not a test.
- **Still not covered:** an **automated** browser↔Android e2e (the manual run
  above as a repeatable test), verification on a **physical device**, and a
  **CI** Android job (existing CI is Linux/macOS/Windows only).
- **Why deferred:** The browser↔Android e2e needs a signaling + browser harness
  reachable from the device/emulator network — heavier than the milestone; all
  its constituent pieces are already individually verified on-device.
- **Acceptance:** An Android e2e (port the `test/e2e/` browser-interop pattern
  with the Android app as one peer) showing a received video stream rendered;
  a green run on a physical device; an Android `flutter test integration_test`
  job in CI.

### Android capture: camera / mic / speaker

- **Found:** 2026-06-15, Android-support milestone (explicit non-goal).
- **Detail:** No Android capture/playback. macOS uses AVFoundation
  ([dart/src/wmd_media.m](dart/src/wmd_media.m)); Android needs Camera2 +
  AudioRecord (capture) and AudioTrack (playback). The first milestone is
  receive + render only; sending uses `FakeVideoSource`.
- **Why deferred:** Out of scope for the receive/render milestone; capture-
  backend work is large and platform-specific.
- **Acceptance:** `getUserMedia`-equivalent camera + mic capture and speaker
  playback on Android, wired through the Flutter plugin's native side.

---

## Refactoring

> Entries below come from the 2026-07-03 refactoring audit (parallel
> sub-agents over pc/media, transport/ice/dtls, rtp/srtp/sctp/sdp, and
> crypto/codec). These are **code smells, not bugs** — duplication, god
> classes, and convention drift. Suggested order: ByteReader/ByteWriter
> first (it unlocks several others), then the DTLS v13 merge, then the god
> class splits.

### SdpParser.parse returns Result but has no Err path

- **Found:** 2026-07-03, refactoring audit (remainder of "SDP parser/builder
  cleanups" — the dedup items (a)–(c) shipped 2026-07-05 with snapshot tests)
- **Detail:** `SdpParser.parse` returns `Result` but never `Err` — broken
  input parses as `Ok`. Decision-shaped contract fix: either validate
  (missing `v=`/`m=` → `Err`) or drop the `Result` wrapper. Needs an owner
  decision on which contract the callers want.
- **Why deferred:** API-contract decision, shippable separately.
- **Acceptance:** `parse` validates or loses the `Result` wrapper; callers
  updated accordingly.

### Over-long methods (>80 lines) to split

- **Found:** 2026-07-03, refactoring audit
- **Detail:** Worst offenders beyond those covered above: v13 server
  `_sendServerFlight` (~170 lines), v13 client `_handleServerFinished`
  (~113), v1.2 `_handleClientHello` (~95) / `_sendServerFlight` /
  `_sendClientFlight`, ICE `_handleIceTimer` / `_handleBindingRequest`,
  `RtcpTransportCc.build` (~100, classify→chunk→serialize in one),
  [rtp/packet.dart:368-465](dart/lib/rtp/packet.dart#L368-L465).
- **Why deferred:** Pure readability; fold into whichever branch touches each
  file next rather than a dedicated pass.
- **Acceptance:** Opportunistic, method-by-method — split into phase-named
  private helpers (no behavior change) when a branch touches the file; strike
  through as they land. Not a single-PR item.

### Small consistency items (batch)

- **Found:** 2026-07-03, refactoring audit
- **Detail:** Cheap, independent fixes:
  - `sendRtp` doc comment has a pasted-in duplicate summary line mid-comment
    ([events.dart:371-376](dart/lib/peer_connection/events.dart#L371-L376)).
  - `core`'s `StateError` shadows Dart's built-in — rename to
    `ProtocolStateError` (also update the sealed-error list in CLAUDE.md,
    which documents `StateError` by name).
  - `IceStateMachine.processInput` adds a `localIp` param not in the
    `ProtocolStateMachine` signature it `@override`s.
  - RTCP packet types 200–206 as bare literals in both `packet.dart` and
    `parser.dart`; VP8/H264 descriptor bit masks; `payloadType <= 34` static
    ranges in `_resolveTrackKind` — name the constants.
  - `openh264_bindings.g.dart` sits beside hand-written code while other
    codecs keep generated bindings in subdirectories — move under
    `h264/openh264/`.
  - (The inline raw-byte FIR builder moved to the "FIR command sequence
    number hard-coded to 1" entry in RTP / RTCP / SDP, where it ships with
    the seq-number fix.)
- **Why deferred:** Each is minutes of work; recorded so they aren't lost.
- **Acceptance:** Item-by-item; strike through as they land.

### Public barrel exports internal protocol types

- **Found:** 2026-07-03, refactoring audit
- **Detail:** [webdartc.dart](dart/lib/webdartc.dart) (~L41–66) exports
  crypto/stun/srtp/rtp internals ("for testing / advanced use") alongside the
  W3C surface, so protocol internals are part of the public contract.
- **Why deferred:** Needs an API-surface decision, and is breaking for any
  caller importing internals through the main barrel.
- **Acceptance:** Internals move to a separate `webdartc_internal.dart` barrel
  (or under `src/` with tests importing relatively); `webdartc.dart` keeps
  only the W3C-facing surface.
