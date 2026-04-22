import 'dart:typed_data';

import 'crypto_backend.dart';

/// ECDSA P-256 self-signed certificate for DTLS.
///
/// Uses Security.framework on macOS, OpenSSL on Linux.
final class EcdsaCertificate {
  final EcdsaBackend _impl;

  /// Raw DER bytes of the self-signed X.509 certificate.
  Uint8List get derBytes => _impl.derBytes;

  /// SHA-256 fingerprint as a colon-separated uppercase hex string.
  /// e.g. "AB:CD:EF:..."
  String get sha256Fingerprint => _impl.sha256Fingerprint;

  EcdsaCertificate._(this._impl);

  /// Generate a self-signed ECDSA P-256 certificate suitable for DTLS.
  ///
  /// The certificate is a minimal X.509 v3 DER encoding with:
  ///   - Subject/Issuer: CN=webdartc
  ///   - Validity: now → now+1year
  ///   - Public key: EC P-256
  ///   - Signature: ECDSA-SHA256
  static EcdsaCertificate selfSigned() => EcdsaCertificate._(createEcdsaBackend());

  /// Sign [message] with this certificate's private key (ECDSA-SHA256).
  ///
  /// Returns the DER-encoded ECDSA signature.
  Uint8List sign(Uint8List message) => _impl.sign(message);

  /// Sign a pre-hashed digest (SHA-256 already applied).
  Uint8List signDigest(Uint8List digest) => _impl.signDigest(digest);

  void dispose() => _impl.dispose();
}
