// Android crypto backend, served by the platform JCA (java.security /
// javax.crypto, backed by Conscrypt/BoringSSL) through `package:jni`.
//
// This is the Android analogue of macOS=Security.framework and Windows=CNG:
// an OS-maintained native crypto provider reached over JNI rather than a
// bundled OpenSSL. All JNI plumbing lives in [Jca]; this file maps the six
// `crypto_backend.dart` interfaces onto it.
//
// Two primitives are NOT routed through JCA, matching the macOS backend:
//   - ChaCha20-Poly1305 reuses the pure-Dart RFC 8439 reference
//     (`chacha20_poly1305_pure.dart`) — Android's JCA only gained
//     ChaCha20-Poly1305 at API 28 and the pure version is already shipping.
//   - The self-signed DTLS certificate DER is assembled by the shared
//     pure-Dart `X509Der`, identical to every other backend.
//
// Only instantiated on Android (the `crypto_backend.dart` factories guard
// every constructor with `Platform.isAndroid`), so importing this file on
// other platforms is safe — `package:jni` is never touched there.
import 'dart:typed_data';

import 'package:jni/jni.dart';

import 'aes_gcm.dart' show AesGcmResult;
import 'chacha20_poly1305.dart' show AeadResult;
import 'chacha20_poly1305_pure.dart' as cc20p1305;
import 'crypto_backend.dart';
import 'jca.dart';
import 'sha256.dart';
import 'x509_der.dart';

// ── AES-CM (AES-ECB single block) ──────────────────────────────────────────

final class AndroidAesCmBackend implements AesCmBackend {
  @override
  Uint8List aesEcbEncryptBlock(Uint8List key, Uint8List block) {
    assert(block.length == 16);
    return Jca.i.aesEcbEncryptBlock(key, block);
  }
}

// ── AES-GCM ────────────────────────────────────────────────────────────────

final class AndroidAesGcmBackend implements AesGcmBackend {
  @override
  AesGcmResult encrypt(
      Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
    final r = Jca.i.aesGcmEncrypt(key, nonce, plaintext, aad);
    return AesGcmResult(ciphertext: r.ciphertext, tag: r.tag);
  }

  @override
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext,
          Uint8List expectedTag, Uint8List aad) =>
      Jca.i.aesGcmDecrypt(key, nonce, ciphertext, expectedTag, aad);
}

// ── ChaCha20-Poly1305 (pure Dart, as on macOS) ──────────────────────────────

final class AndroidChaCha20Poly1305Backend
    implements ChaCha20Poly1305Backend {
  @override
  AeadResult encrypt(
      Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
    final r = cc20p1305.aeadEncrypt(key, nonce, plaintext, aad);
    return AeadResult(ciphertext: r.ciphertext, tag: r.tag);
  }

  @override
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext,
          Uint8List expectedTag, Uint8List aad) =>
      cc20p1305.aeadDecrypt(key, nonce, ciphertext, expectedTag, aad);
}

// ── ECDH ────────────────────────────────────────────────────────────────────

final class AndroidEcdhBackend implements EcdhBackend {
  final EcP256KeyPair _keyPair;
  final JObject _ecParams;
  @override
  final Uint8List publicKeyBytes;

  AndroidEcdhBackend._(this._keyPair, this._ecParams)
      : publicKeyBytes = _keyPair.publicKeyBytes;

  factory AndroidEcdhBackend() {
    final kp = Jca.i.generateEcP256KeyPair();
    final params = Jca.i.ecParamsOf(kp.public);
    return AndroidEcdhBackend._(kp, params);
  }

  @override
  Uint8List computeSharedSecret(Uint8List peerPublicKeyBytes) {
    final peer = Jca.i.importEcPublicKey(peerPublicKeyBytes, _ecParams);
    if (peer == null) {
      throw StateError('invalid peer EC public key');
    }
    final secret = Jca.i.ecdhSharedSecret(_keyPair.private, peer);
    peer.release();
    return secret;
  }

  @override
  void dispose() {
    _keyPair.release();
    _ecParams.release();
  }
}

// ── ECDSA ───────────────────────────────────────────────────────────────────

final class AndroidEcdsaBackend implements EcdsaBackend {
  final EcP256KeyPair _keyPair;
  @override
  final Uint8List derBytes;
  @override
  final String sha256Fingerprint;

  AndroidEcdsaBackend._(this._keyPair, this.derBytes, this.sha256Fingerprint);

  factory AndroidEcdsaBackend() {
    final kp = Jca.i.generateEcP256KeyPair();
    final tbs = X509Der.buildTbsCertificate(kp.publicKeyBytes);
    final signature = Jca.i.ecdsaSign(kp.private, tbs, 'SHA256withECDSA');
    final cert = X509Der.buildCertificate(tbs, signature);
    return AndroidEcdsaBackend._(kp, cert, Sha256.fingerprint(cert));
  }

  @override
  Uint8List sign(Uint8List message) =>
      Jca.i.ecdsaSign(_keyPair.private, message, 'SHA256withECDSA');

  @override
  Uint8List signDigest(Uint8List digest) =>
      Jca.i.ecdsaSign(_keyPair.private, digest, 'NONEwithECDSA');

  @override
  void dispose() => _keyPair.release();
}

// ── ECDSA verify (stateless) ────────────────────────────────────────────────

final class AndroidEcdsaVerifyBackend implements EcdsaVerifyBackend {
  @override
  bool verifyP256Sha256({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    final pub = Jca.i.importEcPublicKey(publicKey, Jca.i.p256Params);
    if (pub == null) return false;
    final ok = Jca.i.ecdsaVerifySha256(pub, message, signature);
    pub.release();
    return ok;
  }
}
