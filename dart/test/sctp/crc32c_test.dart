import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';
import 'package:webdartc/sctp/crc32c.dart';

void main() {
  group('SctpCrc32c', () {
    // RFC 3720 Appendix B.4 test vector
    test('CRC-32c("123456789") = 0xE3069283', () {
      final data = Uint8List.fromList('123456789'.codeUnits);
      expect(SctpCrc32c.compute(data), equals(0xE3069283));
    });

    test('CRC-32c of empty data = 0x00000000', () {
      expect(SctpCrc32c.compute(Uint8List(0)), equals(0x00000000));
    });

    test('CRC-32c differs from CRC-32', () {
      final data = Uint8List.fromList('123456789'.codeUnits);
      final crc32c = SctpCrc32c.compute(data);
      final crc32 = Crc32c.compute(data); // ITU V.42 CRC-32
      expect(crc32c, isNot(equals(crc32)),
          reason: 'CRC-32c and CRC-32 must produce different results');
    });
  });
}
