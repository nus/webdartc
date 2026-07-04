// Platform-abstracted crypto backend interfaces and factory.
import 'dart:typed_data';

import '../core/platform_dispatch.dart';
import 'aes_gcm.dart' show AesGcmResult;
import 'chacha20_poly1305.dart' show AeadResult;
import 'boringssl_backend.dart';
import 'macos_backend.dart';
import 'windows_backend.dart';

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

// Linux + Android share the BoringSSL backend (statically-linked libcrypto via
// the bundled webdartc_crypto wrapper); macOS=Security.framework, Windows=CNG.
EcdhBackend createEcdhBackend() => forPlatform(
      macos: MacosEcdhBackend.new,
      posix: BoringSslEcdhBackend.new,
      windows: WindowsEcdhBackend.new,
    );

EcdsaBackend createEcdsaBackend() => forPlatform(
      macos: MacosEcdsaBackend.new,
      posix: BoringSslEcdsaBackend.new,
      windows: WindowsEcdsaBackend.new,
    );

final EcdsaVerifyBackend ecdsaVerifyBackend = _createEcdsaVerify();

EcdsaVerifyBackend _createEcdsaVerify() => forPlatform(
      macos: MacosEcdsaVerifyBackend.new,
      posix: BoringSslEcdsaVerifyBackend.new,
      windows: WindowsEcdsaVerifyBackend.new,
    );

AesCmBackend _createAesCm() => forPlatform(
      macos: MacosAesCmBackend.new,
      posix: BoringSslAesCmBackend.new,
      windows: WindowsAesCmBackend.new,
    );

AesGcmBackend _createAesGcm() => forPlatform(
      macos: MacosAesGcmBackend.new,
      posix: BoringSslAesGcmBackend.new,
      windows: WindowsAesGcmBackend.new,
    );

ChaCha20Poly1305Backend _createChaCha20Poly1305() => forPlatform(
      macos: MacosChaCha20Poly1305Backend.new,
      posix: BoringSslChaCha20Poly1305Backend.new,
      windows: WindowsChaCha20Poly1305Backend.new,
    );
