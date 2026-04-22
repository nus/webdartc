import 'dart:typed_data';

import '../crypto/aes_gcm.dart';
import '../crypto/hkdf.dart';

/// Supported DTLS 1.2 cipher suites.
enum CipherSuite {
  /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
  ecdhEcdsaAes128GcmSha256(0xC0, 0x2B),

  /// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xC009) — fallback
  ecdhEcdsaAes128CbcSha(0xC0, 0x09);

  final int major;
  final int minor;
  const CipherSuite(this.major, this.minor);
}

/// DTLS 1.2 key block derived from master secret (RFC 5246 §6.3).
final class DtlsKeyBlock {
  // For AES-128-GCM: 16-byte key + 4-byte implicit nonce (per side)
  final Uint8List clientWriteKey;
  final Uint8List serverWriteKey;
  final Uint8List clientWriteIv; // 4 bytes for GCM
  final Uint8List serverWriteIv;

  const DtlsKeyBlock({
    required this.clientWriteKey,
    required this.serverWriteKey,
    required this.clientWriteIv,
    required this.serverWriteIv,
  });

  /// Derive key block from master secret using PRF-SHA256 (RFC 5246 §6.3).
  ///
  /// key_block = PRF(master_secret, "key expansion",
  ///                 server_random + client_random)
  static DtlsKeyBlock derive({
    required Uint8List masterSecret,
    required Uint8List clientRandom,
    required Uint8List serverRandom,
    required CipherSuite suite,
  }) {
    // seed = server_random || client_random
    final seed = Uint8List(serverRandom.length + clientRandom.length + 13);
    final label = 'key expansion'.codeUnits;
    seed.setRange(0, label.length, label);
    seed.setRange(
      label.length,
      label.length + serverRandom.length,
      serverRandom,
    );
    seed.setRange(
      label.length + serverRandom.length,
      label.length + serverRandom.length + clientRandom.length,
      clientRandom,
    );

    // For AES-128-GCM: 2*(16 key + 4 IV) = 40 bytes
    final keyMaterial = Hkdf.prfSha256(masterSecret, seed, 40);

    return DtlsKeyBlock(
      clientWriteKey: keyMaterial.sublist(0, 16),
      serverWriteKey: keyMaterial.sublist(16, 32),
      clientWriteIv: keyMaterial.sublist(32, 36),
      serverWriteIv: keyMaterial.sublist(36, 40),
    );
  }
}

/// AEAD record encryption/decryption for DTLS 1.2 with AES-128-GCM.
///
/// Per RFC 5246 §6.2.3.3 / RFC 5288.
abstract final class AeadRecord {
  AeadRecord._();

  /// Encrypt a DTLS record payload.
  ///
  /// [epoch] and [seqNum] are used to construct the nonce.
  static Uint8List encrypt({
    required Uint8List key,
    required Uint8List implicitIv, // 4 bytes
    required int epoch,
    required int seqNum,
    required int contentType,
    required Uint8List plaintext,
  }) {
    // Explicit nonce: 8 bytes = epoch(2) || seqNum(6)
    final explicitNonce = Uint8List(8);
    explicitNonce[0] = (epoch >> 8) & 0xFF;
    explicitNonce[1] = epoch & 0xFF;
    explicitNonce[2] = (seqNum >> 40) & 0xFF;
    explicitNonce[3] = (seqNum >> 32) & 0xFF;
    explicitNonce[4] = (seqNum >> 24) & 0xFF;
    explicitNonce[5] = (seqNum >> 16) & 0xFF;
    explicitNonce[6] = (seqNum >> 8) & 0xFF;
    explicitNonce[7] = seqNum & 0xFF;

    // Full nonce: implicit(4) || explicit(8) = 12 bytes
    final nonce = Uint8List(12);
    nonce.setRange(0, 4, implicitIv);
    nonce.setRange(4, 12, explicitNonce);

    // AAD: seqNum(8) || contentType(1) || version(2) || length(2)
    final aad = _buildAad(epoch, seqNum, contentType, plaintext.length);

    final result = AesGcm.encrypt(key, nonce, plaintext, aad: aad);

    // Output: explicit_nonce(8) || ciphertext || tag(16)
    final out = Uint8List(8 + result.ciphertext.length + result.tag.length);
    out.setRange(0, 8, explicitNonce);
    out.setRange(8, 8 + result.ciphertext.length, result.ciphertext);
    out.setRange(8 + result.ciphertext.length, out.length, result.tag);
    return out;
  }

  /// Decrypt a DTLS record payload.
  static Uint8List? decrypt({
    required Uint8List key,
    required Uint8List implicitIv,
    required int epoch,
    required int seqNum,
    required int contentType,
    required Uint8List ciphertextWithNonceAndTag,
  }) {
    if (ciphertextWithNonceAndTag.length < 8 + 16) return null;
    final explicitNonce = ciphertextWithNonceAndTag.sublist(0, 8);
    final ciphertext = ciphertextWithNonceAndTag.sublist(
      8,
      ciphertextWithNonceAndTag.length - 16,
    );
    final tag = ciphertextWithNonceAndTag.sublist(
      ciphertextWithNonceAndTag.length - 16,
    );

    final nonce = Uint8List(12);
    nonce.setRange(0, 4, implicitIv);
    nonce.setRange(4, 12, explicitNonce);

    final aad = _buildAad(epoch, seqNum, contentType, ciphertext.length);
    return AesGcm.decrypt(
      key,
      nonce,
      ciphertext,
      Uint8List.fromList(tag),
      aad: aad,
    );
  }

  static Uint8List _buildAad(
    int epoch,
    int seqNum,
    int contentType,
    int plaintextLen,
  ) {
    final aad = Uint8List(13);
    // seq_num: epoch(2) || seqNum_48bit(6)
    aad[0] = (epoch >> 8) & 0xFF;
    aad[1] = epoch & 0xFF;
    aad[2] = (seqNum >> 40) & 0xFF;
    aad[3] = (seqNum >> 32) & 0xFF;
    aad[4] = (seqNum >> 24) & 0xFF;
    aad[5] = (seqNum >> 16) & 0xFF;
    aad[6] = (seqNum >> 8) & 0xFF;
    aad[7] = seqNum & 0xFF;
    // content_type
    aad[8] = contentType;
    // version: DTLS 1.2 = 0xFEFD
    aad[9] = 0xFE;
    aad[10] = 0xFD;
    // plaintext length
    aad[11] = (plaintextLen >> 8) & 0xFF;
    aad[12] = plaintextLen & 0xFF;
    return aad;
  }
}
