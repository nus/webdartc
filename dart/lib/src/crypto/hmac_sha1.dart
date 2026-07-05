import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pkg_crypto;

import 'constant_time.dart';

/// HMAC-SHA1 using package:crypto.
abstract final class HmacSha1 {
  HmacSha1._();

  static const int digestLength = 20;
  static const int digest80BitLength = 10;

  /// Compute HMAC-SHA1(key, data) — returns 20 bytes.
  static Uint8List compute(Uint8List key, Uint8List data) {
    final hmac = pkg_crypto.Hmac(pkg_crypto.sha1, key);
    final digest = hmac.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  /// Compute the 80-bit (10-byte) truncation used in STUN MESSAGE-INTEGRITY.
  static Uint8List compute80(Uint8List key, Uint8List data) {
    return compute(key, data).sublist(0, digest80BitLength);
  }

  /// Constant-time HMAC-SHA1 verification against a stored MAC.
  static bool verify(Uint8List key, Uint8List data, Uint8List mac) {
    return constantTimeEquals(compute(key, data), mac);
  }

  /// Constant-time 80-bit HMAC-SHA1 verification.
  static bool verify80(Uint8List key, Uint8List data, Uint8List mac) {
    if (mac.length != digest80BitLength) return false;
    final full = compute(key, data);
    return constantTimeEquals(
        Uint8List.sublistView(full, 0, digest80BitLength), mac);
  }
}
