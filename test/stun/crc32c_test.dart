import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('Crc32c', () {
    // Note: Despite the class name, Crc32c implements CRC-32 (ITU V.42)
    // for STUN FINGERPRINT (RFC 5389 §15.5), NOT CRC-32c (Castagnoli).
    // CRC-32("123456789") = 0xCBF43926 (ITU V.42 test vector)
    test('CRC-32("123456789") = 0xCBF43926', () {
      final data = Uint8List.fromList('123456789'.codeUnits);
      expect(Crc32c.compute(data), equals(0xCBF43926));
    });

    test('CRC-32 of empty data = 0x00000000', () {
      expect(Crc32c.compute(Uint8List(0)), equals(0x00000000));
    });

    test('STUN FINGERPRINT XOR constant', () {
      // STUN FINGERPRINT = CRC-32(msg) XOR 0x5354554E (RFC 5389 §15.5)
      final data = Uint8List.fromList('123456789'.codeUnits);
      final fp = Crc32c.compute(data) ^ 0x5354554E;
      expect(fp, equals(0xCBF43926 ^ 0x5354554E));
    });
  });
}
