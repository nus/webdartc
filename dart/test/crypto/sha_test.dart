import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('Sha256', () {
    test('hash returns 32 bytes', () {
      expect(Sha256.hash(Uint8List.fromList('abc'.codeUnits)).length, equals(32));
    });

    test('hash is deterministic', () {
      final data = Uint8List.fromList('test message'.codeUnits);
      expect(Sha256.hash(data), equals(Sha256.hash(data)));
    });

    test('different inputs give different hashes', () {
      final h1 = Sha256.hash(Uint8List.fromList('abc'.codeUnits));
      final h2 = Sha256.hash(Uint8List.fromList('abd'.codeUnits));
      expect(h1, isNot(equals(h2)));
    });

    test('returns 32 bytes', () {
      expect(Sha256.hash(Uint8List(0)).length, equals(32));
    });

    // NIST FIPS 180-4 test vector
    test('NIST FIPS 180-4: SHA-256("abc")', () {
      final hash = Sha256.hash(Uint8List.fromList('abc'.codeUnits));
      final expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
      ];
      expect(hash, equals(Uint8List.fromList(expected)));
    });
  });

  group('Sha1', () {
    test('hash("") returns correct digest', () {
      final hash = Sha1.hash(Uint8List(0));
      // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
      final expected = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09,
      ];
      expect(hash, equals(Uint8List.fromList(expected)));
    });
  });
}
