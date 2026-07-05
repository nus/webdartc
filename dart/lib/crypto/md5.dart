import 'dart:typed_data';

import 'package:crypto/crypto.dart' as pkg_crypto;

import '../core/hex.dart';

/// MD5 using package:crypto.
abstract final class Md5 {
  Md5._();

  static const int digestLength = 16;

  static Uint8List hash(Uint8List data) {
    final digest = pkg_crypto.md5.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  static String hashHex(Uint8List data) => hex(hash(data));
}
