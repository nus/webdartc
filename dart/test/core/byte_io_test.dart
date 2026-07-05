import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/core/byte_io.dart';

void main() {
  group('random-access reads', () {
    final data = Uint8List.fromList([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
    ]);

    test('readU16', () {
      expect(readU16(data, 0), equals(0x0123));
      expect(readU16(data, 3), equals(0x6789));
    });

    test('readU24', () {
      expect(readU24(data, 0), equals(0x012345));
      expect(readU24(data, 5), equals(0xABCDEF));
    });

    test('readU32', () {
      expect(readU32(data, 0), equals(0x01234567));
      expect(readU32(data, 4), equals(0x89ABCDEF));
    });

    test('readU32 of a high-bit value stays unsigned', () {
      final d = Uint8List.fromList([0xFF, 0xFF, 0xFF, 0xFF]);
      expect(readU32(d, 0), equals(0xFFFFFFFF));
    });

    test('readU48', () {
      expect(readU48(data, 0), equals(0x0123456789AB));
    });

    test('readU64', () {
      expect(readU64(data, 0), equals(0x0123456789ABCDEF));
    });
  });

  group('random-access writes', () {
    test('writeU16 / writeU24 / writeU32', () {
      final d = Uint8List(4);
      writeU16(d, 0, 0x0123);
      expect(d, equals([0x01, 0x23, 0, 0]));
      writeU24(d, 0, 0xABCDEF);
      expect(d, equals([0xAB, 0xCD, 0xEF, 0]));
      writeU32(d, 0, 0x89ABCDEF);
      expect(d, equals([0x89, 0xAB, 0xCD, 0xEF]));
    });

    test('writes mask excess high bits', () {
      final d = Uint8List(2);
      writeU16(d, 0, 0x12345);
      expect(d, equals([0x23, 0x45]));
    });

    test('writeU48 / writeU64 round-trip', () {
      final d = Uint8List(8);
      writeU48(d, 0, 0x0123456789AB);
      expect(readU48(d, 0), equals(0x0123456789AB));
      writeU64(d, 0, 0x0123456789ABCDEF);
      expect(readU64(d, 0), equals(0x0123456789ABCDEF));
    });
  });

  group('ByteReader', () {
    test('advances across mixed-width reads', () {
      final d = Uint8List.fromList([
        0x01, // u8
        0x02, 0x03, // u16
        0x04, 0x05, 0x06, // u24
        0x07, 0x08, 0x09, 0x0A, // u32
        0xAA, 0xBB, // bytes
        0xCC,
      ]);
      final r = ByteReader(d);
      expect(r.readU8(), equals(0x01));
      expect(r.readU16(), equals(0x0203));
      expect(r.readU24(), equals(0x040506));
      expect(r.readU32(), equals(0x0708090A));
      expect(r.readBytes(2), equals([0xAA, 0xBB]));
      expect(r.offset, equals(12));
      expect(r.remaining, equals(1));
      expect(r.canRead(1), isTrue);
      expect(r.canRead(2), isFalse);
      r.skip(1);
      expect(r.remaining, equals(0));
    });

    test('readU48 / readU64 advance correctly', () {
      final d = Uint8List.fromList([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // u48
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A, // u64
      ]);
      final r = ByteReader(d);
      expect(r.readU48(), equals(0x0123456789AB));
      expect(r.readU64(), equals(42));
      expect(r.remaining, equals(0));
    });

    test('starts at a caller-supplied offset', () {
      final d = Uint8List.fromList([0xFF, 0xFF, 0x12, 0x34]);
      final r = ByteReader(d, 2);
      expect(r.readU16(), equals(0x1234));
    });

    test('readBytes returns a copy', () {
      final d = Uint8List.fromList([1, 2, 3]);
      final r = ByteReader(d);
      final b = r.readBytes(3);
      d[0] = 99;
      expect(b, equals([1, 2, 3]));
    });
  });

  group('ByteWriter', () {
    test('appends big-endian values', () {
      final w = ByteWriter();
      w.writeU8(0x01);
      w.writeU16(0x0203);
      w.writeU24(0x040506);
      w.writeU32(0x0708090A);
      w.writeBytes([0xAA, 0xBB]);
      expect(w.length, equals(12));
      expect(
        w.takeBytes(),
        equals([
          0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
          0xAA, 0xBB,
        ]),
      );
    });

    test('writeU48 / writeU64 match the random-access writers', () {
      final w = ByteWriter();
      w.writeU48(0x0123456789AB);
      w.writeU64(0x0123456789ABCDEF);
      final expected = Uint8List(14);
      writeU48(expected, 0, 0x0123456789AB);
      writeU64(expected, 6, 0x0123456789ABCDEF);
      expect(w.takeBytes(), equals(expected));
    });
  });
}
