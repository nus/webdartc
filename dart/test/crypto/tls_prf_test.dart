import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('TlsPrf.sha256 (RFC 5246 §5)', () {
    final secret = Uint8List.fromList('secret'.codeUnits);
    final seed = Uint8List.fromList('seed'.codeUnits);

    test('produces the requested number of bytes', () {
      for (final len in [1, 12, 40, 48, 100]) {
        expect(TlsPrf.sha256(secret, seed, len).length, len);
      }
    });

    test('is deterministic', () {
      expect(TlsPrf.sha256(secret, seed, 48),
          equals(TlsPrf.sha256(secret, seed, 48)));
    });

    test('a shorter request is a prefix of a longer one (P_hash stream)', () {
      final long = TlsPrf.sha256(secret, seed, 64);
      final short = TlsPrf.sha256(secret, seed, 20);
      expect(short, equals(long.sublist(0, 20)));
    });

    test('distinct secret or seed yields distinct output', () {
      final base = TlsPrf.sha256(secret, seed, 32);
      expect(TlsPrf.sha256(Uint8List.fromList('other'.codeUnits), seed, 32),
          isNot(equals(base)));
      expect(TlsPrf.sha256(secret, Uint8List.fromList('other'.codeUnits), 32),
          isNot(equals(base)));
    });
  });
}
