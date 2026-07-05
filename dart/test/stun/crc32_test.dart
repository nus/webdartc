import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/stun/crc32.dart';

void main() {
  group('Crc32', () {
    // STUN FINGERPRINT uses CRC-32 (ITU V.42, RFC 8489 §14.7), NOT CRC-32c
    // (Castagnoli) — that's the separate SCTP checksum.
    // CRC-32("123456789") = 0xCBF43926 (ITU V.42 test vector)
    test('CRC-32("123456789") = 0xCBF43926', () {
      final data = Uint8List.fromList('123456789'.codeUnits);
      expect(Crc32.compute(data), equals(0xCBF43926));
    });

    test('CRC-32 of empty data = 0x00000000', () {
      expect(Crc32.compute(Uint8List(0)), equals(0x00000000));
    });

    test('STUN FINGERPRINT XOR constant', () {
      // STUN FINGERPRINT = CRC-32(msg) XOR 0x5354554E (RFC 8489 §14.7)
      final data = Uint8List.fromList('123456789'.codeUnits);
      final fp = Crc32.compute(data) ^ 0x5354554E;
      expect(fp, equals(0xCBF43926 ^ 0x5354554E));
    });
  });
}
