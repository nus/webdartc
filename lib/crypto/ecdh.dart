import 'dart:typed_data';

import 'crypto_backend.dart';

/// ECDH P-256 key pair and shared secret computation.
///
/// Uses Security.framework on macOS, OpenSSL on Linux.
final class EcdhKeyPair {
  final EcdhBackend _impl;

  /// Raw public key bytes in uncompressed form (0x04 || X || Y = 65 bytes).
  Uint8List get publicKeyBytes => _impl.publicKeyBytes;

  EcdhKeyPair._(this._impl);

  /// Generate a new P-256 key pair.
  static EcdhKeyPair generate() => EcdhKeyPair._(createEcdhBackend());

  /// Compute the ECDH shared secret using [peerPublicKeyBytes].
  ///
  /// [peerPublicKeyBytes] must be 65 bytes (uncompressed P-256 point).
  /// Returns the 32-byte X coordinate of the shared point.
  Uint8List computeSharedSecret(Uint8List peerPublicKeyBytes) =>
      _impl.computeSharedSecret(peerPublicKeyBytes);

  void dispose() => _impl.dispose();
}
