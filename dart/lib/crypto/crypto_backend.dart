// Platform-abstracted crypto backend interfaces and factory.
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'aes_gcm.dart' show AesGcmResult;
import 'chacha20_poly1305.dart' show AeadResult;
import 'macos_backend.dart';
import 'linux_backend.dart';

// ── Abstract interfaces ─────────────────────────────────────────────────────

/// AES-ECB single-block encrypt (used by AES-CM counter mode).
abstract interface class AesCmBackend {
  Uint8List aesEcbEncryptBlock(Uint8List key, Uint8List block);
}

/// AES-GCM authenticated encryption/decryption.
abstract interface class AesGcmBackend {
  AesGcmResult encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad);
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext, Uint8List expectedTag, Uint8List aad);
}

/// ChaCha20-Poly1305 authenticated encryption/decryption (RFC 8439).
abstract interface class ChaCha20Poly1305Backend {
  AeadResult encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad);
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext, Uint8List expectedTag, Uint8List aad);
}

/// ECDH P-256 key pair operations.
abstract interface class EcdhBackend {
  Uint8List get publicKeyBytes;
  Uint8List computeSharedSecret(Uint8List peerPublicKeyBytes);
  void dispose();
}

/// ECDSA P-256 certificate + signing operations.
abstract interface class EcdsaBackend {
  Uint8List get derBytes;
  String get sha256Fingerprint;
  Uint8List sign(Uint8List message);
  Uint8List signDigest(Uint8List digest);
  void dispose();
}

/// Stateless ECDSA P-256 SHA-256 signature verification.
abstract interface class EcdsaVerifyBackend {
  /// [publicKey]: 65-byte uncompressed point (0x04 || X || Y).
  /// [message]:   bytes that were signed (SHA-256 is applied internally).
  /// [signature]: DER-encoded ECDSA signature.
  bool verifyP256Sha256({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  });
}

// ── Factory (lazy, platform-selected) ───────────────────────────────────────

final AesCmBackend aesCmBackend = _createAesCm();
final AesGcmBackend aesGcmBackend = _createAesGcm();
final ChaCha20Poly1305Backend chaCha20Poly1305Backend = _createChaCha20Poly1305();

EcdhBackend createEcdhBackend() {
  if (Platform.isMacOS) return MacosEcdhBackend();
  if (Platform.isLinux) return LinuxEcdhBackend();
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}

EcdsaBackend createEcdsaBackend() {
  if (Platform.isMacOS) return MacosEcdsaBackend();
  if (Platform.isLinux) return LinuxEcdsaBackend();
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}

final EcdsaVerifyBackend ecdsaVerifyBackend = _createEcdsaVerify();

EcdsaVerifyBackend _createEcdsaVerify() {
  if (Platform.isMacOS) return MacosEcdsaVerifyBackend();
  if (Platform.isLinux) return LinuxEcdsaVerifyBackend();
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}

AesCmBackend _createAesCm() {
  if (Platform.isMacOS) return MacosAesCmBackend();
  if (Platform.isLinux) return LinuxAesCmBackend();
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}

AesGcmBackend _createAesGcm() {
  if (Platform.isMacOS) return MacosAesGcmBackend();
  if (Platform.isLinux) return LinuxAesGcmBackend();
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}

ChaCha20Poly1305Backend _createChaCha20Poly1305() {
  if (Platform.isMacOS) return MacosChaCha20Poly1305Backend();
  if (Platform.isLinux) return LinuxChaCha20Poly1305Backend();
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}
