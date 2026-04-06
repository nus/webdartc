// Platform-abstracted crypto backend interfaces and factory.
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'aes_gcm.dart' show AesGcmResult;
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

// ── Factory (lazy, platform-selected) ───────────────────────────────────────

final AesCmBackend aesCmBackend = _createAesCm();
final AesGcmBackend aesGcmBackend = _createAesGcm();

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
