import 'dart:typed_data';

import 'crypto_backend.dart';

/// Result of an AEAD encryption: ciphertext + 16-byte authentication tag.
///
/// Used by [ChaCha20Poly1305] (and any future AEAD primitives that share
/// this two-output shape). This is intentionally a separate type from
/// [AesGcmResult] so callers don't accidentally feed a GCM tag into a
/// ChaCha20-Poly1305 decryption (or vice versa).
final class AeadResult {
  final Uint8List ciphertext;
  final Uint8List tag; // 16 bytes

  const AeadResult({required this.ciphertext, required this.tag});
}

/// ChaCha20-Poly1305 AEAD (RFC 8439).
///
/// Used by DTLS 1.3 to implement the `TLS_CHACHA20_POLY1305_SHA256`
/// (0x1303) cipher suite (RFC 8446 §B.4). The key schedule, nonce
/// derivation and AAD/record framing all live in `lib/dtls/v13/`; this
/// module only provides the raw single-shot AEAD primitive.
///
/// Platform backends:
///
/// * **Linux** — OpenSSL `EVP_chacha20_poly1305()` via FFI (see
///   [LinuxChaCha20Poly1305Backend] in `linux_backend.dart`).
/// * **macOS** — pure-Dart implementation following RFC 8439 §2 — exposed
///   via [MacosChaCha20Poly1305Backend] in `macos_backend.dart`. Apple's
///   CommonCrypto does not provide ChaCha20-Poly1305, and CryptoKit is
///   Swift-only, so pure Dart is the only option without bundling a
///   third-party native library. This is acceptable for ephemeral DTLS
///   handshake records but is **not** constant-time; long-running data
///   records on macOS should ideally use a native implementation
///   eventually.
abstract final class ChaCha20Poly1305 {
  ChaCha20Poly1305._();

  static const int keyLength = 32;
  static const int nonceLength = 12;
  static const int tagLength = 16;

  /// Encrypt [plaintext] with ChaCha20-Poly1305.
  ///
  /// [key]   : 32 bytes
  /// [nonce] : 12 bytes
  /// [aad]   : additional authenticated data (may be empty)
  static AeadResult encrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext, {
    Uint8List? aad,
  }) {
    assert(key.length == keyLength);
    assert(nonce.length == nonceLength);
    return chaCha20Poly1305Backend.encrypt(
        key, nonce, plaintext, aad ?? Uint8List(0));
  }

  /// Decrypt and authenticate a ChaCha20-Poly1305 ciphertext.
  ///
  /// Returns null if authentication fails.
  static Uint8List? decrypt(
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertext,
    Uint8List tag, {
    Uint8List? aad,
  }) {
    assert(key.length == keyLength);
    assert(nonce.length == nonceLength);
    assert(tag.length == tagLength);
    return chaCha20Poly1305Backend.decrypt(
        key, nonce, ciphertext, tag, aad ?? Uint8List(0));
  }
}
