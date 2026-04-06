import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('Hkdf', () {
    // RFC 5869 Appendix A.1
    // Hash = SHA-256
    // IKM  = 0x0b0b...0b (22 octets)
    // salt = 0x000102...0c (13 octets)
    // info = 0xf0f1...f9 (10 octets)
    // L    = 42
    // PRK  = 0x077709366259...
    // OKM  = 0x3cb25f...

    test('RFC 5869 Appendix A.1 extract', () {
      final ikm  = Uint8List.fromList(List.filled(22, 0x0b));
      final salt = Uint8List.fromList(
          List.generate(13, (i) => i)); // 0x00..0x0c
      final prk = Hkdf.extract(salt, ikm);
      expect(prk.length, equals(32));
      // PRK = 077709366259...
      expect(prk[0], equals(0x07));
      expect(prk[1], equals(0x77));
    });

    test('RFC 5869 Appendix A.1 extract+expand', () {
      final ikm  = Uint8List.fromList(List.filled(22, 0x0b));
      final salt = Uint8List.fromList(List.generate(13, (i) => i));
      final info = Uint8List.fromList(List.generate(10, (i) => 0xf0 + i));
      final okm  = Hkdf.deriveKey(secret: ikm, salt: salt, info: info, length: 42);
      expect(okm.length, equals(42));
      // First byte of OKM from RFC 5869 Appendix A.1 = 0x3c
      expect(okm[0], equals(0x3c));
    });

    test('prfSha256 returns correct length', () {
      final secret = Uint8List.fromList('secret'.codeUnits);
      final seed   = Uint8List.fromList('seed'.codeUnits);
      final out    = Hkdf.prfSha256(secret, seed, 48);
      expect(out.length, equals(48));
    });
  });
}
