import 'dart:typed_data';

import '../crypto/hkdf.dart';

/// DTLS SRTP key material derivation (RFC 5764 §4.2, RFC 5705).
///
/// Uses the TLS Keying Material Exporter with:
///   label = "EXTRACTOR-dtls_srtp"
///   no context
abstract final class DtlsKeyMaterial {
  DtlsKeyMaterial._();

  static const String _srtpLabel = 'EXTRACTOR-dtls_srtp';

  /// Derive SRTP key material from the DTLS master secret.
  ///
  /// [masterSecret] : 48-byte DTLS master secret
  /// [clientRandom] : 32-byte ClientHello.random
  /// [serverRandom] : 32-byte ServerHello.random
  /// [length]       : number of bytes to export (default 60 for AES-128-CM-HMAC-SHA1-80)
  ///
  /// Returns [length] bytes of key material to be split:
  ///   client_write_SRTP_master_key   [0..15]
  ///   server_write_SRTP_master_key   [16..31]
  ///   client_write_SRTP_master_salt  [32..43]
  ///   server_write_SRTP_master_salt  [44..55]
  ///
  /// RFC 5705 §4: exported_keying_material =
  ///   PRF(master_secret, label, client_random || server_random)[0..length-1]
  static Uint8List exportSrtpKeyMaterial({
    required Uint8List masterSecret,
    required Uint8List clientRandom,
    required Uint8List serverRandom,
    int length = 60,
  }) {
    final labelBytes = Uint8List.fromList(_srtpLabel.codeUnits);
    // RFC 5764 §4.2: PRF(master_secret, "EXTRACTOR-dtls_srtp",
    //                    client_random + server_random)
    final seed = Uint8List(
        labelBytes.length + clientRandom.length + serverRandom.length);
    seed.setRange(0, labelBytes.length, labelBytes);
    seed.setRange(
        labelBytes.length, labelBytes.length + clientRandom.length, clientRandom);
    seed.setRange(
        labelBytes.length + clientRandom.length, seed.length, serverRandom);

    return Hkdf.prfSha256(masterSecret, seed, length);
  }

  /// Compute the DTLS 1.2 master secret from the premaster secret.
  ///
  /// master_secret = PRF(premaster_secret, "master secret",
  ///                     client_random || server_random)[0..47]
  static Uint8List computeMasterSecret({
    required Uint8List premasterSecret,
    required Uint8List clientRandom,
    required Uint8List serverRandom,
  }) {
    const label = 'master secret';
    final labelBytes = Uint8List.fromList(label.codeUnits);
    final seed = Uint8List(labelBytes.length + clientRandom.length + serverRandom.length);
    seed.setRange(0, labelBytes.length, labelBytes);
    seed.setRange(labelBytes.length, labelBytes.length + clientRandom.length, clientRandom);
    seed.setRange(
        labelBytes.length + clientRandom.length,
        seed.length,
        serverRandom);

    return Hkdf.prfSha256(premasterSecret, seed, 48);
  }

  /// Compute extended master secret (RFC 7627).
  ///
  /// master_secret = PRF(premaster_secret, "extended master secret",
  ///                     session_hash)[0..47]
  /// where session_hash = Hash(handshake_messages) up to and including
  /// the ClientKeyExchange message.
  static Uint8List computeExtendedMasterSecret({
    required Uint8List premasterSecret,
    required Uint8List sessionHash,
  }) {
    const label = 'extended master secret';
    final labelBytes = Uint8List.fromList(label.codeUnits);
    final seed = Uint8List(labelBytes.length + sessionHash.length);
    seed.setRange(0, labelBytes.length, labelBytes);
    seed.setRange(labelBytes.length, seed.length, sessionHash);
    return Hkdf.prfSha256(premasterSecret, seed, 48);
  }

  /// Compute Finished verify_data (RFC 5246 §7.4.9).
  ///
  /// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]
  static Uint8List computeFinishedVerifyData({
    required Uint8List masterSecret,
    required Uint8List handshakeHash, // SHA-256 of all handshake messages
    required bool isClient,
  }) {
    final label = isClient ? 'client finished' : 'server finished';
    final labelBytes = Uint8List.fromList(label.codeUnits);
    final seed = Uint8List(labelBytes.length + handshakeHash.length);
    seed.setRange(0, labelBytes.length, labelBytes);
    seed.setRange(labelBytes.length, seed.length, handshakeHash);
    return Hkdf.prfSha256(masterSecret, seed, 12);
  }
}
