import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/hmac_sha256.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);
  String hexOf(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  group('HmacSha256', () {
    test('digest is 32 bytes', () {
      final mac = HmacSha256.compute(Uint8List(0), Uint8List(0));
      expect(mac.length, equals(32));
    });

    // RFC 4231 Test Case 1
    test('RFC 4231 Test Case 1', () {
      final key = bytes(List<int>.filled(20, 0x0b));
      final data = bytes('Hi There'.codeUnits);
      final mac = HmacSha256.compute(key, data);
      expect(
        hexOf(mac),
        equals(
          'b0344c61d8db38535ca8afceaf0bf12b'
          '881dc200c9833da726e9376c2e32cff7',
        ),
      );
    });

    // RFC 4231 Test Case 2
    test('RFC 4231 Test Case 2', () {
      final key = bytes('Jefe'.codeUnits);
      final data = bytes('what do ya want for nothing?'.codeUnits);
      final mac = HmacSha256.compute(key, data);
      expect(
        hexOf(mac),
        equals(
          '5bdcc146bf60754e6a042426089575c7'
          '5a003f089d2739839dec58b964ec3843',
        ),
      );
    });

    test('verify accepts a valid tag', () {
      final key = bytes(List<int>.generate(32, (i) => i));
      final data = bytes(List<int>.generate(64, (i) => 0xA0 ^ i));
      final mac = HmacSha256.compute(key, data);
      expect(HmacSha256.verify(key, data, mac), isTrue);
    });

    test('verify rejects a tampered tag', () {
      final key = bytes(List<int>.generate(32, (i) => i));
      final data = bytes(List<int>.generate(64, (i) => 0xA0 ^ i));
      final mac = HmacSha256.compute(key, data);
      mac[0] ^= 0x01;
      expect(HmacSha256.verify(key, data, mac), isFalse);
    });

    test('verify rejects a wrong-length tag', () {
      final key = bytes(List<int>.generate(32, (i) => i));
      expect(
        HmacSha256.verify(key, Uint8List(0), Uint8List(31)),
        isFalse,
      );
    });
  });
}
