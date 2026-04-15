import 'dart:math';
import 'dart:typed_data';

/// Cryptographically secure random byte generation.
///
/// Uses Dart's [Random.secure()] which delegates to the OS CSPRNG.
abstract final class Csprng {
  Csprng._();

  static final _rng = Random.secure();

  /// Returns [n] cryptographically secure random bytes.
  static Uint8List randomBytes(int n) {
    final bytes = Uint8List(n);
    for (var i = 0; i < n; i++) {
      bytes[i] = _rng.nextInt(256);
    }
    return bytes;
  }

  /// Returns a hex string of [n] random bytes (2n characters).
  static String randomHex(int n) {
    return randomBytes(n)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }

  /// Returns a random 32-bit unsigned integer.
  static int randomUint32() {
    final bytes = randomBytes(4);
    return bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3];
  }

  /// Returns a random 64-bit value as two 32-bit parts [high, low].
  static (int high, int low) randomUint64() {
    return (randomUint32(), randomUint32());
  }
}
