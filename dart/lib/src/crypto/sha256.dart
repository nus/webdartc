import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pkg_crypto;

import '../core/hex.dart';

/// SHA-256 using package:crypto.
abstract final class Sha256 {
  Sha256._();

  static const int digestLength = 32;

  static Uint8List hash(Uint8List data) {
    final digest = pkg_crypto.sha256.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  /// Returns a lowercase hex string of the SHA-256 digest.
  static String hashHex(Uint8List data) => hex(hash(data));

  /// Uppercase, colon-separated hex of the SHA-256 digest — the format DTLS
  /// uses for certificate fingerprints (`a=fingerprint`, RFC 8122). Every
  /// ECDSA backend reports its self-signed cert fingerprint this way.
  static String fingerprint(Uint8List data) =>
      hex(hash(data), separator: ':', upperCase: true);
}
