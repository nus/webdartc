// Linux crypto backend using OpenSSL libcrypto.
// All DynamicLibrary.open calls are behind lazy static fields —
// safe to import on any platform, only fails if actually instantiated on non-Linux.
import 'dart:ffi';
import 'dart:typed_data';

import 'crypto_backend.dart';
import 'native_alloc.dart';
import 'openssl.dart';
import 'sha256.dart';
import 'x509_der.dart';
import 'aes_gcm.dart' show AesGcmResult;

// ── AES-CM (AES-ECB single block) ──────────────────────────────────────────

final class LinuxAesCmBackend implements AesCmBackend {
  @override
  Uint8List aesEcbEncryptBlock(Uint8List key, Uint8List block) {
    assert(block.length == 16);
    final ssl = ossl;

    final cipher = key.length == 32 ? ssl.evpAes256Ecb() : ssl.evpAes128Ecb();
    final ctx = ssl.evpCipherCtxNew();
    if (ctx == nullptr) throw StateError('EVP_CIPHER_CTX_new failed');

    final keyPtr = libcAlloc.allocate<Uint8>(key.length);
    final inPtr = libcAlloc.allocate<Uint8>(16);
    final outPtr = libcAlloc.allocate<Uint8>(32); // EVP may write up to block+16
    final outLenPtr = libcAlloc.allocate<Int32>(1);

    try {
      for (var i = 0; i < key.length; i++) { keyPtr[i] = key[i]; }
      for (var i = 0; i < 16; i++) { inPtr[i] = block[i]; }

      if (ssl.evpEncryptInitEx(ctx, cipher, nullptr, keyPtr, nullptr) != 1) {
        throw StateError('EVP_EncryptInit_ex failed');
      }
      outLenPtr.value = 0;
      if (ssl.evpEncryptUpdate(ctx, outPtr, outLenPtr, inPtr, 16) != 1) {
        throw StateError('EVP_EncryptUpdate failed');
      }

      return fromNative(outPtr, 16);
    } finally {
      ssl.evpCipherCtxFree(ctx);
      libcAlloc.free(keyPtr);
      libcAlloc.free(inPtr);
      libcAlloc.free(outPtr);
      libcAlloc.free(outLenPtr);
    }
  }
}

// ── AES-GCM ────────────────────────────────────────────────────────────────

final class LinuxAesGcmBackend implements AesGcmBackend {
  static const int _tagLength = 16;

  @override
  AesGcmResult encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
    final ssl = ossl;
    final cipher = key.length == 32 ? ssl.evpAes256Gcm() : ssl.evpAes128Gcm();
    final ctx = ssl.evpCipherCtxNew();
    if (ctx == nullptr) throw StateError('EVP_CIPHER_CTX_new failed');

    final keyPtr = libcAlloc.allocate<Uint8>(key.length);
    final ivPtr = libcAlloc.allocate<Uint8>(nonce.length);
    final aadPtr = libcAlloc.allocate<Uint8>(aad.isEmpty ? 1 : aad.length);
    final inPtr = libcAlloc.allocate<Uint8>(plaintext.isEmpty ? 1 : plaintext.length);
    final outPtr = libcAlloc.allocate<Uint8>(plaintext.isEmpty ? 1 : plaintext.length);
    final tagPtr = libcAlloc.allocate<Uint8>(_tagLength);
    final outLenPtr = libcAlloc.allocate<Int32>(1);

    try {
      for (var i = 0; i < key.length; i++) { keyPtr[i] = key[i]; }
      for (var i = 0; i < nonce.length; i++) { ivPtr[i] = nonce[i]; }
      for (var i = 0; i < aad.length; i++) { aadPtr[i] = aad[i]; }
      for (var i = 0; i < plaintext.length; i++) { inPtr[i] = plaintext[i]; }

      // Init cipher
      ssl.evpEncryptInitEx(ctx, cipher, nullptr, nullptr, nullptr);
      // Set IV length
      ssl.evpCipherCtxCtrl(ctx, ssl.evpCtrlGcmSetIvlen, nonce.length, nullptr);
      // Set key and IV
      ssl.evpEncryptInitEx(ctx, nullptr, nullptr, keyPtr, ivPtr);
      // AAD
      if (aad.isNotEmpty) {
        ssl.evpEncryptUpdate(ctx, nullptr, outLenPtr, aadPtr, aad.length);
      }
      // Encrypt
      outLenPtr.value = 0;
      ssl.evpEncryptUpdate(ctx, outPtr, outLenPtr, inPtr, plaintext.length);
      // Finalize
      final tmpPtr = libcAlloc.allocate<Uint8>(16);
      final tmpLenPtr = libcAlloc.allocate<Int32>(1);
      ssl.evpEncryptFinalEx(ctx, tmpPtr, tmpLenPtr);
      libcAlloc.free(tmpPtr);
      libcAlloc.free(tmpLenPtr);
      // Get tag
      ssl.evpCipherCtxCtrl(ctx, ssl.evpCtrlGcmGetTag, _tagLength, tagPtr.cast());

      return AesGcmResult(
        ciphertext: fromNative(outPtr, plaintext.length),
        tag: fromNative(tagPtr, _tagLength),
      );
    } finally {
      ssl.evpCipherCtxFree(ctx);
      libcAlloc.free(keyPtr);
      libcAlloc.free(ivPtr);
      libcAlloc.free(aadPtr);
      libcAlloc.free(inPtr);
      libcAlloc.free(outPtr);
      libcAlloc.free(tagPtr);
      libcAlloc.free(outLenPtr);
    }
  }

  @override
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext, Uint8List expectedTag, Uint8List aad) {
    final ssl = ossl;
    final cipher = key.length == 32 ? ssl.evpAes256Gcm() : ssl.evpAes128Gcm();
    final ctx = ssl.evpCipherCtxNew();
    if (ctx == nullptr) throw StateError('EVP_CIPHER_CTX_new failed');

    final keyPtr = libcAlloc.allocate<Uint8>(key.length);
    final ivPtr = libcAlloc.allocate<Uint8>(nonce.length);
    final aadPtr = libcAlloc.allocate<Uint8>(aad.isEmpty ? 1 : aad.length);
    final inPtr = libcAlloc.allocate<Uint8>(ciphertext.isEmpty ? 1 : ciphertext.length);
    final outPtr = libcAlloc.allocate<Uint8>(ciphertext.isEmpty ? 1 : ciphertext.length);
    final tagPtr = libcAlloc.allocate<Uint8>(_tagLength);
    final outLenPtr = libcAlloc.allocate<Int32>(1);

    try {
      for (var i = 0; i < key.length; i++) { keyPtr[i] = key[i]; }
      for (var i = 0; i < nonce.length; i++) { ivPtr[i] = nonce[i]; }
      for (var i = 0; i < aad.length; i++) { aadPtr[i] = aad[i]; }
      for (var i = 0; i < ciphertext.length; i++) { inPtr[i] = ciphertext[i]; }
      for (var i = 0; i < _tagLength; i++) { tagPtr[i] = expectedTag[i]; }

      ssl.evpDecryptInitEx(ctx, cipher, nullptr, nullptr, nullptr);
      ssl.evpCipherCtxCtrl(ctx, ssl.evpCtrlGcmSetIvlen, nonce.length, nullptr);
      ssl.evpDecryptInitEx(ctx, nullptr, nullptr, keyPtr, ivPtr);
      // AAD
      if (aad.isNotEmpty) {
        ssl.evpDecryptUpdate(ctx, nullptr, outLenPtr, aadPtr, aad.length);
      }
      // Decrypt
      outLenPtr.value = 0;
      ssl.evpDecryptUpdate(ctx, outPtr, outLenPtr, inPtr, ciphertext.length);
      // Set expected tag before finalize
      ssl.evpCipherCtxCtrl(ctx, ssl.evpCtrlGcmSetTag, _tagLength, tagPtr.cast());
      // Finalize — returns <= 0 on auth failure
      final tmpPtr = libcAlloc.allocate<Uint8>(16);
      final tmpLenPtr = libcAlloc.allocate<Int32>(1);
      final ret = ssl.evpDecryptFinalEx(ctx, tmpPtr, tmpLenPtr);
      libcAlloc.free(tmpPtr);
      libcAlloc.free(tmpLenPtr);

      if (ret <= 0) return null; // authentication failed

      return fromNative(outPtr, ciphertext.length);
    } finally {
      ssl.evpCipherCtxFree(ctx);
      libcAlloc.free(keyPtr);
      libcAlloc.free(ivPtr);
      libcAlloc.free(aadPtr);
      libcAlloc.free(inPtr);
      libcAlloc.free(outPtr);
      libcAlloc.free(tagPtr);
      libcAlloc.free(outLenPtr);
    }
  }
}

// ── ECDH ────────────────────────────────────────────────────────────────────

final class LinuxEcdhBackend implements EcdhBackend, Finalizable {
  final Pointer<Void> _ecKey; // EC_KEY*
  @override
  final Uint8List publicKeyBytes;

  static final _finalizer = NativeFinalizer(
    ossl.lib.lookup<NativeFunction<Void Function(Pointer<Void>)>>('EC_KEY_free'),
  );

  LinuxEcdhBackend._({required Pointer<Void> ecKey, required this.publicKeyBytes})
      : _ecKey = ecKey {
    _finalizer.attach(this, _ecKey, detach: this);
  }

  factory LinuxEcdhBackend() {
    final ssl = ossl;
    final ecKey = ssl.ecKeyNewByCurveName(ssl.nidP256);
    if (ecKey == nullptr) throw StateError('EC_KEY_new_by_curve_name failed');
    if (ssl.ecKeyGenerateKey(ecKey) != 1) {
      ssl.ecKeyFree(ecKey);
      throw StateError('EC_KEY_generate_key failed');
    }

    // Extract uncompressed public key bytes (65 bytes: 0x04 || X || Y)
    final group = ssl.ecKeyGet0Group(ecKey);
    final pubPoint = ssl.ecKeyGet0PublicKey(ecKey);
    final bufLen = ssl.ecPointPoint2Oct(
        group, pubPoint, ssl.pointConversionUncompressed, nullptr, 0, nullptr);
    if (bufLen == 0) throw StateError('EC_POINT_point2oct size query failed');

    final buf = libcAlloc.allocate<Uint8>(bufLen);
    try {
      ssl.ecPointPoint2Oct(
          group, pubPoint, ssl.pointConversionUncompressed, buf, bufLen, nullptr);
      final pubBytes = fromNative(buf, bufLen);
      return LinuxEcdhBackend._(ecKey: ecKey, publicKeyBytes: pubBytes);
    } finally {
      libcAlloc.free(buf);
    }
  }

  @override
  Uint8List computeSharedSecret(Uint8List peerPublicKeyBytes) {
    final ssl = ossl;
    final group = ssl.ecKeyGet0Group(_ecKey);

    // Import peer public key
    final peerPoint = ssl.ecPointNew(group);
    if (peerPoint == nullptr) throw StateError('EC_POINT_new failed');

    final peerBuf = libcAlloc.allocate<Uint8>(peerPublicKeyBytes.length);
    try {
      for (var i = 0; i < peerPublicKeyBytes.length; i++) { peerBuf[i] = peerPublicKeyBytes[i]; }
      final result = ssl.ecPointOct2Point(
          group, peerPoint, peerBuf, peerPublicKeyBytes.length, nullptr);
      if (result == nullptr) {
        ssl.ecPointFree(peerPoint);
        throw StateError('EC_POINT_oct2point failed');
      }
    } finally {
      libcAlloc.free(peerBuf);
    }

    // Compute shared secret (32 bytes for P-256)
    final outBuf = libcAlloc.allocate<Uint8>(32);
    try {
      final outLen = ssl.ecdhComputeKey(outBuf, 32, peerPoint, _ecKey, nullptr);
      ssl.ecPointFree(peerPoint);
      if (outLen <= 0) throw StateError('ECDH_compute_key failed');
      return fromNative(outBuf, outLen);
    } finally {
      libcAlloc.free(outBuf);
    }
  }

  @override
  void dispose() {
    _finalizer.detach(this);
    ossl.ecKeyFree(_ecKey);
  }
}

// ── ECDSA ───────────────────────────────────────────────────────────────────

final class LinuxEcdsaBackend implements EcdsaBackend, Finalizable {
  @override final Uint8List derBytes;
  @override final String sha256Fingerprint;
  final Pointer<Void> _pkey; // EVP_PKEY* (owns the EC_KEY)

  static final _finalizer = NativeFinalizer(ossl.evpPkeyFreePtr);

  LinuxEcdsaBackend._({
    required this.derBytes,
    required this.sha256Fingerprint,
    required Pointer<Void> pkey,
  }) : _pkey = pkey {
    _finalizer.attach(this, _pkey, detach: this);
  }

  factory LinuxEcdsaBackend() {
    final ssl = ossl;

    // Generate EC P-256 key
    final ecKey = ssl.ecKeyNewByCurveName(ssl.nidP256);
    if (ecKey == nullptr) throw StateError('EC_KEY_new_by_curve_name failed');
    if (ssl.ecKeyGenerateKey(ecKey) != 1) {
      ssl.ecKeyFree(ecKey);
      throw StateError('EC_KEY_generate_key failed');
    }

    // Extract uncompressed public key bytes
    final group = ssl.ecKeyGet0Group(ecKey);
    final pubPoint = ssl.ecKeyGet0PublicKey(ecKey);
    final bufLen = ssl.ecPointPoint2Oct(
        group, pubPoint, ssl.pointConversionUncompressed, nullptr, 0, nullptr);
    final buf = libcAlloc.allocate<Uint8>(bufLen);
    Uint8List pubKeyBytes;
    try {
      ssl.ecPointPoint2Oct(
          group, pubPoint, ssl.pointConversionUncompressed, buf, bufLen, nullptr);
      pubKeyBytes = fromNative(buf, bufLen);
    } finally {
      libcAlloc.free(buf);
    }

    // Wrap in EVP_PKEY for DigestSign
    final pkey = ssl.evpPkeyNew();
    if (pkey == nullptr) {
      ssl.ecKeyFree(ecKey);
      throw StateError('EVP_PKEY_new failed');
    }
    // EVP_PKEY_set1_EC_KEY increments refcount; we still own ecKey
    if (ssl.evpPkeySet1EcKey(pkey, ecKey) != 1) {
      ssl.evpPkeyFree(pkey);
      ssl.ecKeyFree(ecKey);
      throw StateError('EVP_PKEY_set1_EC_KEY failed');
    }
    ssl.ecKeyFree(ecKey); // pkey now holds a ref

    // Build certificate
    final tbs = X509Der.buildTbsCertificate(pubKeyBytes);
    final signature = _signWithPkey(pkey, tbs);
    final cert = X509Der.buildCertificate(tbs, signature);
    final fpBytes = Sha256.hash(cert);
    final fp = fpBytes.map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase()).join(':');

    return LinuxEcdsaBackend._(derBytes: cert, sha256Fingerprint: fp, pkey: pkey);
  }

  @override
  Uint8List sign(Uint8List message) => _signWithPkey(_pkey, message);

  @override
  Uint8List signDigest(Uint8List digest) => _signDigestRaw(_pkey, digest);

  /// Sign a message using EVP_DigestSign (hashes internally with SHA-256).
  static Uint8List _signWithPkey(Pointer<Void> pkey, Uint8List data) {
    final ssl = ossl;
    final mdCtx = ssl.evpMdCtxNew();
    if (mdCtx == nullptr) throw StateError('EVP_MD_CTX_new failed');

    final dataPtr = libcAlloc.allocate<Uint8>(data.isEmpty ? 1 : data.length);
    final sigLenPtr = libcAlloc.allocate<Size>(1);

    try {
      for (var i = 0; i < data.length; i++) { dataPtr[i] = data[i]; }

      // Init with SHA-256
      if (ssl.evpDigestSignInit(mdCtx, nullptr, ssl.evpSha256(), nullptr, pkey) != 1) {
        throw StateError('EVP_DigestSignInit failed');
      }
      // Query signature length
      sigLenPtr.value = 0;
      if (ssl.evpDigestSign(mdCtx, nullptr, sigLenPtr, dataPtr, data.length) != 1) {
        throw StateError('EVP_DigestSign (query len) failed');
      }
      final sigLen = sigLenPtr.value;
      final sigPtr = libcAlloc.allocate<Uint8>(sigLen);
      try {
        sigLenPtr.value = sigLen;
        if (ssl.evpDigestSign(mdCtx, sigPtr, sigLenPtr, dataPtr, data.length) != 1) {
          throw StateError('EVP_DigestSign failed');
        }
        return fromNative(sigPtr, sigLenPtr.value);
      } finally {
        libcAlloc.free(sigPtr);
      }
    } finally {
      ssl.evpMdCtxFree(mdCtx);
      libcAlloc.free(dataPtr);
      libcAlloc.free(sigLenPtr);
    }
  }

  /// Sign a pre-hashed SHA-256 digest using ECDSA_sign.
  static Uint8List _signDigestRaw(Pointer<Void> pkey, Uint8List digest) {
    // For digest signing we need the EC_KEY back from the EVP_PKEY.
    // Use EVP_DigestSign with EVP_sha256() but pass digest directly?
    // Actually, OpenSSL's ECDSA_sign expects the raw digest. But we
    // need the EC_KEY. Instead, we can use EVP_DigestSign with a trick:
    // just sign the digest as a "message" — it will be re-hashed, which is wrong.
    //
    // The correct approach: use EVP_PKEY_sign for raw digest signing.
    // But that's more complex. For simplicity and compatibility with the macOS
    // backend which uses "DigestX962SHA256" (sign pre-hashed digest),
    // we use ECDSA_sign via the EC_KEY extracted from EVP_PKEY.
    final ssl = ossl;

    // Get EC_KEY from EVP_PKEY via EVP_PKEY_get1_EC_KEY
    final ecKey = ssl.evpPkeyGet1EcKey(pkey);
    if (ecKey == nullptr) throw StateError('EVP_PKEY_get1_EC_KEY failed');

    final maxSigLen = ssl.ecdsaSize(ecKey);
    final sigPtr = libcAlloc.allocate<Uint8>(maxSigLen);
    final sigLenPtr = libcAlloc.allocate<Uint32>(1);
    final digestPtr = libcAlloc.allocate<Uint8>(digest.length);

    try {
      for (var i = 0; i < digest.length; i++) { digestPtr[i] = digest[i]; }
      sigLenPtr.value = maxSigLen;
      final ret = ssl.ecdsaSign(0, digestPtr, digest.length, sigPtr, sigLenPtr, ecKey);
      ssl.ecKeyFree(ecKey); // free the ref from get1
      if (ret != 1) throw StateError('ECDSA_sign failed');
      return fromNative(sigPtr, sigLenPtr.value);
    } finally {
      libcAlloc.free(sigPtr);
      libcAlloc.free(sigLenPtr);
      libcAlloc.free(digestPtr);
    }
  }

  @override
  void dispose() {
    _finalizer.detach(this);
    ossl.evpPkeyFree(_pkey);
  }
}
