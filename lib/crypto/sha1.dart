import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pkg_crypto;

/// SHA-1 using package:crypto.
abstract final class Sha1 {
  Sha1._();

  static const int digestLength = 20;

  static Uint8List hash(Uint8List data) {
    final digest = pkg_crypto.sha1.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  static String hashHex(Uint8List data) {
    return hash(data).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
