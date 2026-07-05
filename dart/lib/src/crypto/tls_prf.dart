import 'dart:typed_data';

import 'hmac_sha256.dart';

/// TLS 1.2 / DTLS 1.2 pseudorandom function (RFC 5246 §5).
///
/// This is *not* HKDF (RFC 5869) — DTLS 1.2 key derivation uses the TLS
/// PRF, whereas TLS/DTLS 1.3 uses HKDF. For SHA-256 cipher suites the
/// TLS 1.2 PRF is exactly `P_SHA256`.
abstract final class TlsPrf {
  TlsPrf._();

  /// `P_SHA256(secret, seed)` truncated to [length] bytes (RFC 5246 §5):
  ///
  ///   P_SHA256(secret, seed) = HMAC_SHA256(secret, A(1) + seed) ||
  ///                            HMAC_SHA256(secret, A(2) + seed) || ...
  ///   A(0) = seed, A(i) = HMAC_SHA256(secret, A(i-1))
  static Uint8List sha256(Uint8List secret, Uint8List seed, int length) {
    final out = <int>[];
    var a = Uint8List.fromList(seed); // A(0)
    while (out.length < length) {
      a = HmacSha256.compute(secret, a); // A(i)
      final combined = Uint8List(a.length + seed.length);
      combined.setRange(0, a.length, a);
      combined.setRange(a.length, combined.length, seed);
      out.addAll(HmacSha256.compute(secret, combined));
    }
    return Uint8List.fromList(out.sublist(0, length));
  }
}
