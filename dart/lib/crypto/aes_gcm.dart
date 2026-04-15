import 'dart:typed_data';

import 'crypto_backend.dart';

/// Result of AES-GCM encryption: ciphertext + authentication tag.
final class AesGcmResult {
  final Uint8List ciphertext;
  final Uint8List tag; // 16 bytes

  const AesGcmResult({required this.ciphertext, required this.tag});
}

/// AES-GCM encryption/decryption — used for SRTP with AES-GCM profile (RFC 7714).
///
/// Platform-specific GCM is provided by [AesGcmBackend].
abstract final class AesGcm {
  AesGcm._();

  static const int tagLength = 16;

  /// Encrypt [plaintext] with AES-GCM.
  ///
  /// [key]   : 16 or 32 bytes
  /// [nonce] : 12 bytes (96-bit IV)
  /// [aad]   : additional authenticated data (may be empty)
  static AesGcmResult encrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext, {
    Uint8List? aad,
  }) {
    assert(key.length == 16 || key.length == 32);
    assert(nonce.length == 12);
    return aesGcmBackend.encrypt(key, nonce, plaintext, aad ?? Uint8List(0));
  }

  /// Decrypt and authenticate a GCM ciphertext.
  ///
  /// Returns null if authentication fails.
  static Uint8List? decrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertext,
    Uint8List expectedTag, {
    Uint8List? aad,
  }) {
    assert(key.length == 16 || key.length == 32);
    assert(nonce.length == 12);
    assert(expectedTag.length == tagLength);
    return aesGcmBackend.decrypt(key, nonce, ciphertext, expectedTag, aad ?? Uint8List(0));
  }
}
