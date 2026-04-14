import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

Uint8List hex(String s) {
  final h = s.replaceAll(' ', '');
  return Uint8List.fromList(List.generate(
      h.length ~/ 2, (i) => int.parse(h.substring(i * 2, i * 2 + 2), radix: 16)));
}

void main() {
  group('AesCm', () {
    test('encrypt/decrypt roundtrip', () {
      final key = hex('2b7e151628aed2a6abf7158809cf4f3c');
      final iv = hex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
      final plain = hex('6bc1bee22e409f96e93d7e117393172a');
      final cipher = AesCm.encrypt(key, iv, plain);
      final decrypted = AesCm.decrypt(key, iv, cipher);
      expect(decrypted, equals(plain));
    });

    // RFC 3711 Appendix B.3: AES-CM key derivation test vector
    test('RFC 3711 B.3 — KDF cipher key derivation', () {
      final masterKey = hex('e1f97a0d3e018be0d64fa32c06de4139');
      final iv = hex('0ec675ad498afeebb6960b3aabe60000');

      // AES-CM(key, IV, zeros) = keystream = AES-ECB(key, IV)
      final zeros = Uint8List(16);
      final keystream = AesCm.encrypt(masterKey, iv, zeros);
      final expected = hex('c61e7a93744f39ee10734afe3ff7a087');
      expect(keystream, equals(expected));
    });

    test('multi-block encryption', () {
      final key = hex('2b7e151628aed2a6abf7158809cf4f3c');
      final iv = Uint8List(16);
      final plain = Uint8List(48); // 3 blocks
      for (var i = 0; i < 48; i++) { plain[i] = i; }
      final cipher = AesCm.encrypt(key, iv, plain);
      expect(cipher.length, equals(48));
      final decrypted = AesCm.decrypt(key, iv, cipher);
      expect(decrypted, equals(plain));
    });
  });
}
