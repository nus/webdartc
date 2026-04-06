import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pkg_crypto;

/// HKDF (RFC 5869) implemented using package:crypto HMAC primitives.
///
/// Used for DTLS key derivation and related operations.
abstract final class Hkdf {
  Hkdf._();

  /// HKDF-Extract(salt, ikm) → prk (32 bytes for SHA-256).
  static Uint8List extract(Uint8List salt, Uint8List ikm) {
    // If salt is not provided, use a string of HashLen zeros.
    final effectiveSalt = salt.isEmpty ? Uint8List(32) : salt;
    final hmac = pkg_crypto.Hmac(pkg_crypto.sha256, effectiveSalt);
    final digest = hmac.convert(ikm);
    return Uint8List.fromList(digest.bytes);
  }

  /// HKDF-Expand(prk, info, length) → okm.
  ///
  /// [length] must be <= 255 * 32 (HashLen).
  static Uint8List expand(Uint8List prk, Uint8List info, int length) {
    assert(length > 0 && length <= 255 * 32, 'HKDF expand: invalid length');
    final n = (length + 31) ~/ 32; // ceil(length / HashLen)
    final okm = Uint8List(n * 32);
    var t = Uint8List(0);
    for (var i = 1; i <= n; i++) {
      final input = Uint8List(t.length + info.length + 1);
      input.setRange(0, t.length, t);
      input.setRange(t.length, t.length + info.length, info);
      input[t.length + info.length] = i;
      final hmac = pkg_crypto.Hmac(pkg_crypto.sha256, prk);
      t = Uint8List.fromList(hmac.convert(input).bytes);
      okm.setRange((i - 1) * 32, i * 32, t);
    }
    return Uint8List.sublistView(okm, 0, length);
  }

  /// Combined extract-then-expand.
  ///
  /// [secret] : IKM
  /// [salt]   : optional salt (pass empty for zeros)
  /// [info]   : context label
  /// [length] : output key material length in bytes
  static Uint8List deriveKey({
    required Uint8List secret,
    required Uint8List salt,
    required Uint8List info,
    required int length,
  }) {
    final prk = extract(salt, secret);
    return expand(prk, info, length);
  }

  /// DTLS/TLS PRF-SHA256 as used in RFC 5705 / DTLS 1.2 with SHA-256.
  ///
  /// P_SHA256(secret, seed) = HMAC_SHA256(secret, A(1)+seed) ||
  ///                          HMAC_SHA256(secret, A(2)+seed) || ...
  /// where A(0) = seed, A(i) = HMAC_SHA256(secret, A(i-1))
  static Uint8List prfSha256(Uint8List secret, Uint8List seed, int length) {
    final out = <int>[];
    var a = Uint8List.fromList(seed); // A(0)
    while (out.length < length) {
      // A(i) = HMAC_SHA256(secret, A(i-1))
      a = _hmacSha256(secret, a);
      // HMAC_SHA256(secret, A(i) + seed)
      final combined = Uint8List(a.length + seed.length);
      combined.setRange(0, a.length, a);
      combined.setRange(a.length, combined.length, seed);
      out.addAll(_hmacSha256(secret, combined));
    }
    return Uint8List.fromList(out.sublist(0, length));
  }

  static Uint8List _hmacSha256(Uint8List key, Uint8List data) {
    final hmac = pkg_crypto.Hmac(pkg_crypto.sha256, key);
    return Uint8List.fromList(hmac.convert(data).bytes);
  }
}
