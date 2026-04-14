import 'dart:typed_data';

import 'crypto_backend.dart';

/// AES-128/256-CM (Counter Mode) — RFC 3711 §4.1.1.
///
/// Implemented using AES-ECB to encrypt counter blocks, then XOR with data.
/// Platform-specific AES-ECB is provided by [AesCmBackend].
abstract final class AesCm {
  AesCm._();

  /// Encrypt (or decrypt — CTR is symmetric) [data] with [key] and [iv].
  ///
  /// [key] must be 16 or 32 bytes.
  /// [iv]  must be 16 bytes (counter block).
  ///
  /// RFC 3711 §4.1.1: The counter is the IV with the last 4 bytes (bytes 12-15)
  /// incremented as a 32-bit big-endian integer for each AES block.
  static Uint8List encrypt(Uint8List key, Uint8List iv, Uint8List data) {
    assert(key.length == 16 || key.length == 32, 'AES-CM key must be 16 or 32 bytes');
    assert(iv.length == 16, 'AES-CM IV must be 16 bytes');
    if (data.isEmpty) return Uint8List(0);

    final nBlocks = (data.length + 15) ~/ 16;
    final out = Uint8List(data.length);
    final counterBlock = Uint8List.fromList(iv);
    final backend = aesCmBackend;

    for (var block = 0; block < nBlocks; block++) {
      final keystream = backend.aesEcbEncryptBlock(key, counterBlock);
      final start = block * 16;
      final end = (start + 16).clamp(0, data.length);
      for (var i = start; i < end; i++) {
        out[i] = data[i] ^ keystream[i - start];
      }
      _incrementCounter(counterBlock);
    }

    return out;
  }

  // Decrypt is identical to encrypt for CTR mode.
  static Uint8List decrypt(Uint8List key, Uint8List iv, Uint8List data) =>
      encrypt(key, iv, data);

  /// Convenience wrapper used by SRTP.
  static Uint8List xorKeystream(Uint8List key, Uint8List iv, Uint8List plaintext) {
    return encrypt(key, iv, plaintext);
  }

  /// Increment the 32-bit big-endian counter in bytes 12-15 of the block.
  static void _incrementCounter(Uint8List block) {
    for (var i = 15; i >= 12; i--) {
      block[i]++;
      if (block[i] != 0) break; // no carry
    }
  }
}
