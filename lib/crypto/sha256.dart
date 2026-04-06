import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pkg_crypto;

/// SHA-256 using package:crypto.
abstract final class Sha256 {
  Sha256._();

  static const int digestLength = 32;

  static Uint8List hash(Uint8List data) {
    final digest = pkg_crypto.sha256.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  /// Returns a lowercase hex string of the SHA-256 digest.
  static String hashHex(Uint8List data) {
    return hash(data).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
