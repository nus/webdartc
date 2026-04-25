import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pkg_crypto;

/// HMAC-SHA256 using package:crypto.
///
/// Used for TLS 1.3 Finished verify_data
/// (`HMAC-SHA256(finished_key, transcript_hash)`) and other 32-byte MACs.
abstract final class HmacSha256 {
  HmacSha256._();

  /// HMAC output length in bytes.
  static const int digestLength = 32;

  /// Compute `HMAC-SHA256(key, data)` — always 32 bytes.
  static Uint8List compute(Uint8List key, Uint8List data) {
    final hmac = pkg_crypto.Hmac(pkg_crypto.sha256, key);
    return Uint8List.fromList(hmac.convert(data).bytes);
  }

  /// Constant-time comparison of an HMAC tag.
  static bool verify(Uint8List key, Uint8List data, Uint8List mac) {
    final expected = compute(key, data);
    if (expected.length != mac.length) return false;
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ mac[i];
    }
    return diff == 0;
  }
}
