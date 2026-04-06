import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('Csprng', () {
    test('randomBytes returns requested length', () {
      for (final n in [0, 1, 16, 32, 256]) {
        expect(Csprng.randomBytes(n).length, equals(n));
      }
    });

    test('randomHex returns 2*n characters', () {
      expect(Csprng.randomHex(16).length, equals(32));
    });

    test('successive calls produce different values', () {
      final a = Csprng.randomBytes(16);
      final b = Csprng.randomBytes(16);
      // Vanishingly unlikely to be equal
      expect(a, isNot(equals(b)));
    });

    test('randomUint32 returns non-negative 32-bit value', () {
      final v = Csprng.randomUint32();
      expect(v, greaterThanOrEqualTo(0));
      expect(v, lessThanOrEqualTo(0xFFFFFFFF));
    });
  });
}
