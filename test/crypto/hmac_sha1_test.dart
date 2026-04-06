import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('HmacSha1', () {
    test('compute returns 20 bytes', () {
      final key  = Uint8List.fromList('key'.codeUnits);
      final data = Uint8List.fromList('data'.codeUnits);
      final mac  = HmacSha1.compute(key, data);
      expect(mac.length, equals(20));
    });

    test('compute80 returns 10 bytes', () {
      final key  = Uint8List.fromList('key'.codeUnits);
      final data = Uint8List.fromList('data'.codeUnits);
      final mac  = HmacSha1.compute80(key, data);
      expect(mac.length, equals(10));
    });

    test('verify round-trip', () {
      final key  = Uint8List.fromList('secret'.codeUnits);
      final data = Uint8List.fromList('hello world'.codeUnits);
      final mac  = HmacSha1.compute(key, data);
      expect(HmacSha1.verify(key, data, mac), isTrue);
    });

    test('verify rejects bad mac', () {
      final key  = Uint8List.fromList('secret'.codeUnits);
      final data = Uint8List.fromList('hello world'.codeUnits);
      final badMac = Uint8List(20); // all zeros
      expect(HmacSha1.verify(key, data, badMac), isFalse);
    });

    // RFC 2202 Test Case 1
    test('RFC 2202 Test Case 1', () {
      final key  = Uint8List.fromList(List.filled(20, 0x0b));
      final data = Uint8List.fromList('Hi There'.codeUnits);
      final expected = [
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
        0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
        0xf1, 0x46, 0xbe, 0x00,
      ];
      final mac = HmacSha1.compute(key, data);
      expect(mac, equals(Uint8List.fromList(expected)));
    });

    // RFC 2202 Test Case 2 (STUN MESSAGE-INTEGRITY で使用するパターン)
    test('RFC 2202 Test Case 2', () {
      final key  = Uint8List.fromList('Jefe'.codeUnits);
      final data = Uint8List.fromList('what do ya want for nothing?'.codeUnits);
      final expected = [
        0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
        0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
        0x25, 0x9a, 0x7c, 0x79,
      ];
      final mac = HmacSha1.compute(key, data);
      expect(mac, equals(Uint8List.fromList(expected)));
    });
  });
}
