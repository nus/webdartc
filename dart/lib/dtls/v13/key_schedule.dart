import 'dart:typed_data';

import '../../crypto/hkdf.dart';
import '../../crypto/sha256.dart';

/// TLS 1.3 / DTLS 1.3 key schedule (RFC 8446 §7.1, RFC 9147 §5.4).
///
/// The schedule starts from `early_secret` and chains through
/// `handshake_secret` and `master_secret`. From each "traffic secret" four
/// per-direction values are derived via `HKDF-Expand-Label`:
///
///   write_key    = Expand-Label(traffic, "key",      "", key_length)
///   write_iv     = Expand-Label(traffic, "iv",       "", 12)
///   finished_key = Expand-Label(traffic, "finished", "", hash_length)
///   sn_key       = Expand-Label(traffic, "sn",       "", key_length)  [DTLS]
///
/// This module is hash-agnostic in interface but specialized for SHA-256
/// (the only hash required by the cipher suites webdartc currently
/// negotiates: `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`).
abstract final class TlsV13KeySchedule {
  TlsV13KeySchedule._();

  /// SHA-256 output length in bytes — used as the hash length throughout
  /// the schedule for both supported cipher suites.
  static const int hashLength = 32;

  /// SHA-256 hash of the empty input. Several `Derive-Secret` calls in the
  /// schedule use this when no transcript has accumulated yet.
  static final Uint8List emptyHash = Sha256.hash(Uint8List(0));

  // ── Stage 1: early secret ───────────────────────────────────────────────

  /// `early_secret = HKDF-Extract(0, PSK)` (RFC 8446 §7.1).
  ///
  /// When [psk] is null or empty (no PSK / no resumption — the default
  /// path for WebRTC), the IKM is HashLen zeros.
  static Uint8List computeEarlySecret({Uint8List? psk}) {
    final ikm = (psk == null || psk.isEmpty) ? Uint8List(hashLength) : psk;
    return Hkdf.extract(Uint8List(hashLength), ikm);
  }

  // ── Stage 2: handshake secret ───────────────────────────────────────────

  /// `handshake_secret = HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE)`.
  static Uint8List computeHandshakeSecret({
    required Uint8List earlySecret,
    required Uint8List ecdheSharedSecret,
  }) {
    final derived = Hkdf.deriveSecret(
      secret: earlySecret,
      label: 'derived',
      transcriptHash: emptyHash,
      prefix: Hkdf.dtls13Prefix,
    );
    return Hkdf.extract(derived, ecdheSharedSecret);
  }

  // ── Stage 3: master secret ──────────────────────────────────────────────

  /// `master_secret = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0)`.
  static Uint8List computeMasterSecret({
    required Uint8List handshakeSecret,
  }) {
    final derived = Hkdf.deriveSecret(
      secret: handshakeSecret,
      label: 'derived',
      transcriptHash: emptyHash,
      prefix: Hkdf.dtls13Prefix,
    );
    return Hkdf.extract(derived, Uint8List(hashLength));
  }

  // ── Traffic secrets ─────────────────────────────────────────────────────

  /// `client_handshake_traffic_secret`: `Derive-Secret(handshake, "c hs traffic", CH..SH)`.
  static Uint8List computeClientHandshakeTrafficSecret({
    required Uint8List handshakeSecret,
    required Uint8List chShTranscriptHash,
  }) =>
      Hkdf.deriveSecret(
        secret: handshakeSecret,
        label: 'c hs traffic',
        transcriptHash: chShTranscriptHash,
        prefix: Hkdf.dtls13Prefix,
      );

  /// `server_handshake_traffic_secret`: `Derive-Secret(handshake, "s hs traffic", CH..SH)`.
  static Uint8List computeServerHandshakeTrafficSecret({
    required Uint8List handshakeSecret,
    required Uint8List chShTranscriptHash,
  }) =>
      Hkdf.deriveSecret(
        secret: handshakeSecret,
        label: 's hs traffic',
        transcriptHash: chShTranscriptHash,
        prefix: Hkdf.dtls13Prefix,
      );

  /// `client_application_traffic_secret_0`:
  /// `Derive-Secret(master, "c ap traffic", CH..server-Finished)`.
  static Uint8List computeClientApplicationTrafficSecret({
    required Uint8List masterSecret,
    required Uint8List chServerFinishedTranscriptHash,
  }) =>
      Hkdf.deriveSecret(
        secret: masterSecret,
        label: 'c ap traffic',
        transcriptHash: chServerFinishedTranscriptHash,
        prefix: Hkdf.dtls13Prefix,
      );

  /// `server_application_traffic_secret_0`:
  /// `Derive-Secret(master, "s ap traffic", CH..server-Finished)`.
  static Uint8List computeServerApplicationTrafficSecret({
    required Uint8List masterSecret,
    required Uint8List chServerFinishedTranscriptHash,
  }) =>
      Hkdf.deriveSecret(
        secret: masterSecret,
        label: 's ap traffic',
        transcriptHash: chServerFinishedTranscriptHash,
        prefix: Hkdf.dtls13Prefix,
      );

  /// `exporter_master_secret = Derive-Secret(master, "exp master", CH..server-Finished)`.
  ///
  /// Used by the SRTP keying-material exporter (RFC 9147 §5.5 + RFC 5764).
  static Uint8List computeExporterMasterSecret({
    required Uint8List masterSecret,
    required Uint8List chServerFinishedTranscriptHash,
  }) =>
      Hkdf.deriveSecret(
        secret: masterSecret,
        label: 'exp master',
        transcriptHash: chServerFinishedTranscriptHash,
        prefix: Hkdf.dtls13Prefix,
      );

  // ── Per-direction key/iv/finished_key/sn_key from a traffic secret ──────

  /// Derive the per-record materials from a traffic secret.
  ///
  /// [keyLength] is the AEAD key length (16 for AES-128, 32 for AES-256 /
  /// ChaCha20). The IV length is always 12 for the cipher suites covered
  /// here; `finished_key` length matches the hash length.
  static TrafficKeys deriveTrafficKeys({
    required Uint8List trafficSecret,
    required int keyLength,
  }) {
    final ctx = Uint8List(0);
    return TrafficKeys(
      trafficSecret: trafficSecret,
      writeKey: Hkdf.expandLabel(
        secret: trafficSecret,
        label: 'key',
        context: ctx,
        length: keyLength,
        prefix: Hkdf.dtls13Prefix,
      ),
      writeIv: Hkdf.expandLabel(
        secret: trafficSecret,
        label: 'iv',
        context: ctx,
        length: 12,
        prefix: Hkdf.dtls13Prefix,
      ),
      finishedKey: Hkdf.expandLabel(
        secret: trafficSecret,
        label: 'finished',
        context: ctx,
        length: hashLength,
        prefix: Hkdf.dtls13Prefix,
      ),
      snKey: Hkdf.expandLabel(
        secret: trafficSecret,
        label: 'sn',
        context: ctx,
        length: keyLength,
        prefix: Hkdf.dtls13Prefix,
      ),
    );
  }
}

/// Per-direction key material derived from a single TLS 1.3 traffic secret.
final class TrafficKeys {
  /// The originating traffic secret (e.g. `c hs traffic`). Retained because
  /// `KeyUpdate` derives the next-generation secret from it.
  final Uint8List trafficSecret;

  /// AEAD encryption key (16 bytes for AES-128, 32 bytes for AES-256/ChaCha20).
  final Uint8List writeKey;

  /// Static IV combined with the record sequence number to form the AEAD
  /// nonce (RFC 8446 §5.3). 12 bytes for AES-GCM and ChaCha20-Poly1305.
  final Uint8List writeIv;

  /// HMAC key used to compute the `Finished` message verify_data.
  final Uint8List finishedKey;

  /// AES-ECB key used by the DTLS 1.3 sequence-number encryption (RFC 9147
  /// §4.2.3). For TLS 1.3 over TCP this field is unused but harmless.
  final Uint8List snKey;

  const TrafficKeys({
    required this.trafficSecret,
    required this.writeKey,
    required this.writeIv,
    required this.finishedKey,
    required this.snKey,
  });
}
