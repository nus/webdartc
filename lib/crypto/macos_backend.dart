// macOS crypto backend using CommonCrypto and Security.framework.
// All DynamicLibrary.open calls are behind lazy static fields —
// safe to import on any platform, only fails if actually instantiated on non-macOS.
import 'dart:ffi';
import 'dart:typed_data';

import 'aes_gcm.dart' show AesGcmResult;
import 'common_crypto.dart';
import 'crypto_backend.dart';
import 'security_framework.dart';
import 'sha256.dart';
import 'x509_der.dart';

// ── AES-CM (AES-ECB single block) ──────────────────────────────────────────

final class MacosAesCmBackend implements AesCmBackend {
  static final _cc = CommonCrypto.instance;

  @override
  Uint8List aesEcbEncryptBlock(Uint8List key, Uint8List block) {
    assert(block.length == 16);

    final keyPtr = libcAlloc.allocate<Uint8>(key.length);
    final inPtr = libcAlloc.allocate<Uint8>(16);
    final outPtr = libcAlloc.allocate<Uint8>(16);
    final cryptorPtr = libcAlloc.allocate<CCCryptorRef>(1);
    final movedPtr = libcAlloc.allocate<Size>(1);

    try {
      for (var i = 0; i < key.length; i++) { keyPtr[i] = key[i]; }
      for (var i = 0; i < 16; i++) { inPtr[i] = block[i]; }

      final status = _cc.ccCryptorCreateWithMode(
        kCCEncrypt, kCCModeECB, kCCAlgorithmAES, ccNoPadding,
        nullptr, keyPtr, key.length,
        nullptr, 0, 0, 0, cryptorPtr,
      );
      if (status != kCCSuccess) throw StateError('AES-ECB create failed: $status');

      movedPtr.value = 0;
      final updateStatus = _cc.ccCryptorUpdate(
        cryptorPtr.value, inPtr, 16, outPtr, 16, movedPtr,
      );
      _cc.ccCryptorRelease(cryptorPtr.value);
      if (updateStatus != kCCSuccess) throw StateError('AES-ECB update failed: $updateStatus');

      return fromNative(outPtr, 16);
    } finally {
      libcAlloc.free(keyPtr);
      libcAlloc.free(inPtr);
      libcAlloc.free(outPtr);
      libcAlloc.free(cryptorPtr);
      libcAlloc.free(movedPtr);
    }
  }
}

// ── AES-GCM ────────────────────────────────────────────────────────────────

final class MacosAesGcmBackend implements AesGcmBackend {
  static const int _tagLength = 16;
  static final _cc = CommonCrypto.instance;

  @override
  AesGcmResult encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
    final keyPtr = libcAlloc.allocate<Uint8>(key.length);
    final ivPtr = libcAlloc.allocate<Uint8>(nonce.length);
    final aadPtr = libcAlloc.allocate<Uint8>(aad.isEmpty ? 1 : aad.length);
    final dataInPtr = libcAlloc.allocate<Uint8>(plaintext.isEmpty ? 1 : plaintext.length);
    final dataOutPtr = libcAlloc.allocate<Uint8>(plaintext.isEmpty ? 1 : plaintext.length);
    final tagPtr = libcAlloc.allocate<Uint8>(_tagLength);
    final tagLenPtr = libcAlloc.allocate<Size>(1);

    try {
      for (var i = 0; i < key.length; i++) { keyPtr[i] = key[i]; }
      for (var i = 0; i < nonce.length; i++) { ivPtr[i] = nonce[i]; }
      for (var i = 0; i < aad.length; i++) { aadPtr[i] = aad[i]; }
      for (var i = 0; i < plaintext.length; i++) { dataInPtr[i] = plaintext[i]; }
      tagLenPtr.value = _tagLength;

      final status = _cc.ccCryptorGCM(
        kCCEncrypt, kCCAlgorithmAES,
        keyPtr, key.length, ivPtr, nonce.length,
        aadPtr, aad.length, dataInPtr, plaintext.length,
        dataOutPtr, tagPtr, tagLenPtr,
      );
      if (status != kCCSuccess) throw StateError('CCCryptorGCM encrypt failed: $status');

      return AesGcmResult(
        ciphertext: fromNative(dataOutPtr, plaintext.length),
        tag: fromNative(tagPtr, _tagLength),
      );
    } finally {
      libcAlloc.free(keyPtr);
      libcAlloc.free(ivPtr);
      libcAlloc.free(aadPtr);
      libcAlloc.free(dataInPtr);
      libcAlloc.free(dataOutPtr);
      libcAlloc.free(tagPtr);
      libcAlloc.free(tagLenPtr);
    }
  }

  @override
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext, Uint8List expectedTag, Uint8List aad) {
    final keyPtr = libcAlloc.allocate<Uint8>(key.length);
    final ivPtr = libcAlloc.allocate<Uint8>(nonce.length);
    final aadPtr = libcAlloc.allocate<Uint8>(aad.isEmpty ? 1 : aad.length);
    final dataInPtr = libcAlloc.allocate<Uint8>(ciphertext.isEmpty ? 1 : ciphertext.length);
    final dataOutPtr = libcAlloc.allocate<Uint8>(ciphertext.isEmpty ? 1 : ciphertext.length);
    final tagPtr = libcAlloc.allocate<Uint8>(_tagLength);
    final tagLenPtr = libcAlloc.allocate<Size>(1);

    try {
      for (var i = 0; i < key.length; i++) { keyPtr[i] = key[i]; }
      for (var i = 0; i < nonce.length; i++) { ivPtr[i] = nonce[i]; }
      for (var i = 0; i < aad.length; i++) { aadPtr[i] = aad[i]; }
      for (var i = 0; i < ciphertext.length; i++) { dataInPtr[i] = ciphertext[i]; }
      tagLenPtr.value = _tagLength;

      final status = _cc.ccCryptorGCM(
        kCCDecrypt, kCCAlgorithmAES,
        keyPtr, key.length, ivPtr, nonce.length,
        aadPtr, aad.length, dataInPtr, ciphertext.length,
        dataOutPtr, tagPtr, tagLenPtr,
      );
      if (status != kCCSuccess) throw StateError('CCCryptorGCM decrypt failed: $status');

      var tagMismatch = 0;
      for (var i = 0; i < _tagLength; i++) {
        tagMismatch |= tagPtr[i] ^ expectedTag[i];
      }
      if (tagMismatch != 0) return null;

      return fromNative(dataOutPtr, ciphertext.length);
    } finally {
      libcAlloc.free(keyPtr);
      libcAlloc.free(ivPtr);
      libcAlloc.free(aadPtr);
      libcAlloc.free(dataInPtr);
      libcAlloc.free(dataOutPtr);
      libcAlloc.free(tagPtr);
      libcAlloc.free(tagLenPtr);
    }
  }
}

// ── ECDH ────────────────────────────────────────────────────────────────────

final class MacosEcdhBackend implements EcdhBackend, Finalizable {
  final SecKeyRef _privateKeyRef;
  @override
  final Uint8List publicKeyBytes;

  static final _finalizer = NativeFinalizer(
    DynamicLibrary.open('/System/Library/Frameworks/Security.framework/Security')
        .lookup<NativeFunction<Void Function(Pointer<Void>)>>('CFRelease'),
  );

  MacosEcdhBackend._({required SecKeyRef privateKeyRef, required this.publicKeyBytes})
      : _privateKeyRef = privateKeyRef {
    _finalizer.attach(this, _privateKeyRef.cast(), detach: this);
  }

  factory MacosEcdhBackend() {
    final s = sec;
    final keys = libcAlloc.allocate<Pointer<Void>>(2);
    final vals = libcAlloc.allocate<Pointer<Void>>(2);
    final sizePtr = libcAlloc.allocate<Int32>(1);
    sizePtr.value = 256;
    final sizeNumRef = s.cfNumberCreate(nullptr, kCFNumberSInt32Type, sizePtr.cast());
    try {
      keys[0] = s.kSecAttrKeyType;
      keys[1] = s.kSecAttrKeySizeInBits;
      vals[0] = s.kSecAttrKeyTypeECSECPrimeRandomRef;
      vals[1] = sizeNumRef;
      final attrs = s.cfDictionaryCreate(
        nullptr, keys, vals, 2,
        s.kCFTypeDictionaryKeyCallBacks, s.kCFTypeDictionaryValueCallBacks,
      );
      final errPtr = libcAlloc.allocate<CFErrorRef>(1);
      errPtr.value = nullptr;
      try {
        final privateKey = s.secKeyCreateRandomKey(attrs, errPtr);
        if (privateKey == nullptr) throw StateError('SecKeyCreateRandomKey failed');
        final publicKey = s.secKeyCopyPublicKey(privateKey);
        if (publicKey == nullptr) {
          s.cfRelease(privateKey.cast());
          throw StateError('SecKeyCopyPublicKey failed');
        }
        final pubErrPtr = libcAlloc.allocate<CFErrorRef>(1);
        pubErrPtr.value = nullptr;
        try {
          final pubDataRef = s.secKeyCopyExternalRepresentation(publicKey, pubErrPtr);
          if (pubDataRef == nullptr) {
            s.cfRelease(privateKey.cast());
            s.cfRelease(publicKey.cast());
            throw StateError('SecKeyCopyExternalRepresentation failed');
          }
          final pubBytes = s.cfDataToBytes(pubDataRef);
          s.cfRelease(publicKey.cast());
          return MacosEcdhBackend._(privateKeyRef: privateKey, publicKeyBytes: pubBytes);
        } finally {
          libcAlloc.free(pubErrPtr);
        }
      } finally {
        libcAlloc.free(errPtr);
        s.cfRelease(attrs.cast());
      }
    } finally {
      s.cfRelease(sizeNumRef.cast());
      libcAlloc.free(sizePtr);
      libcAlloc.free(keys);
      libcAlloc.free(vals);
    }
  }

  @override
  Uint8List computeSharedSecret(Uint8List peerPublicKeyBytes) {
    final s = sec;
    final peerKeyData = s.bytesToCFData(peerPublicKeyBytes);
    final keys = libcAlloc.allocate<Pointer<Void>>(2);
    final vals = libcAlloc.allocate<Pointer<Void>>(2);
    try {
      keys[0] = s.kSecAttrKeyType;
      keys[1] = s.kSecAttrKeyClass;
      vals[0] = s.kSecAttrKeyTypeECSECPrimeRandomRef;
      vals[1] = s.kSecAttrKeyClassPublic;
      final attrs = s.cfDictionaryCreate(
        nullptr, keys, vals, 2,
        s.kCFTypeDictionaryKeyCallBacks, s.kCFTypeDictionaryValueCallBacks,
      );
      final errPtr = libcAlloc.allocate<CFErrorRef>(1);
      errPtr.value = nullptr;
      try {
        final peerKey = s.secKeyCreateWithData(peerKeyData, attrs, errPtr);
        s.cfRelease(peerKeyData.cast());
        if (peerKey == nullptr) throw StateError('SecKeyCreateWithData failed');
        try {
          final exchErrPtr = libcAlloc.allocate<CFErrorRef>(1);
          exchErrPtr.value = nullptr;
          try {
            final emptyDict = s.cfDictionaryCreate(
              nullptr, nullptr, nullptr, 0,
              s.kCFTypeDictionaryKeyCallBacks, s.kCFTypeDictionaryValueCallBacks,
            );
            final sharedRef = s.secKeyCopyKeyExchangeResult(
              _privateKeyRef, s.kSecKeyAlgorithmECDHKeyExchangeStandard,
              peerKey, emptyDict, exchErrPtr,
            );
            s.cfRelease(emptyDict.cast());
            if (sharedRef == nullptr) throw StateError('SecKeyCopyKeyExchangeResult failed');
            return s.cfDataToBytes(sharedRef);
          } finally {
            libcAlloc.free(exchErrPtr);
          }
        } finally {
          s.cfRelease(peerKey.cast());
        }
      } finally {
        libcAlloc.free(errPtr);
        s.cfRelease(attrs.cast());
      }
    } finally {
      libcAlloc.free(keys);
      libcAlloc.free(vals);
    }
  }

  @override
  void dispose() {
    _finalizer.detach(this);
    sec.cfRelease(_privateKeyRef.cast());
  }
}

// ── ECDSA ───────────────────────────────────────────────────────────────────

final class MacosEcdsaBackend implements EcdsaBackend, Finalizable {
  @override final Uint8List derBytes;
  @override final String sha256Fingerprint;
  final SecKeyRef _privateKeyRef;

  static final _finalizer = NativeFinalizer(
    DynamicLibrary.open('/System/Library/Frameworks/Security.framework/Security')
        .lookup<NativeFunction<Void Function(Pointer<Void>)>>('CFRelease'),
  );

  MacosEcdsaBackend._({
    required this.derBytes,
    required this.sha256Fingerprint,
    required SecKeyRef privateKeyRef,
  }) : _privateKeyRef = privateKeyRef {
    _finalizer.attach(this, _privateKeyRef.cast(), detach: this);
  }

  factory MacosEcdsaBackend() {
    final s = sec;
    final keysArr = libcAlloc.allocate<Pointer<Void>>(2);
    final valsArr = libcAlloc.allocate<Pointer<Void>>(2);
    final sizePtr = libcAlloc.allocate<Int32>(1);
    sizePtr.value = 256;
    final sizeNum = s.cfNumberCreate(nullptr, kCFNumberSInt32Type, sizePtr.cast());
    try {
      keysArr[0] = s.kSecAttrKeyType;
      keysArr[1] = s.kSecAttrKeySizeInBits;
      valsArr[0] = s.kSecAttrKeyTypeECSECPrimeRandomRef;
      valsArr[1] = sizeNum;
      final attrs = s.cfDictionaryCreate(
        nullptr, keysArr, valsArr, 2,
        s.kCFTypeDictionaryKeyCallBacks, s.kCFTypeDictionaryValueCallBacks,
      );
      final errPtr = libcAlloc.allocate<CFErrorRef>(1);
      errPtr.value = nullptr;
      try {
        final privateKey = s.secKeyCreateRandomKey(attrs, errPtr);
        if (privateKey == nullptr) throw StateError('SecKeyCreateRandomKey failed');
        final publicKey = s.secKeyCopyPublicKey(privateKey);
        if (publicKey == nullptr) {
          s.cfRelease(privateKey.cast());
          throw StateError('SecKeyCopyPublicKey failed');
        }
        try {
          final pubErrPtr = libcAlloc.allocate<CFErrorRef>(1);
          pubErrPtr.value = nullptr;
          final pubDataRef = s.secKeyCopyExternalRepresentation(publicKey, pubErrPtr);
          libcAlloc.free(pubErrPtr);
          if (pubDataRef == nullptr) throw StateError('SecKeyCopyExternalRepresentation failed');
          final pubKeyBytes = s.cfDataToBytes(pubDataRef);

          final tbs = X509Der.buildTbsCertificate(pubKeyBytes);
          final signature = _signRaw(privateKey, tbs, digest: false);
          final cert = X509Der.buildCertificate(tbs, signature);
          final fpBytes = Sha256.hash(cert);
          final fp = fpBytes.map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase()).join(':');

          return MacosEcdsaBackend._(derBytes: cert, sha256Fingerprint: fp, privateKeyRef: privateKey);
        } finally {
          s.cfRelease(publicKey.cast());
        }
      } finally {
        libcAlloc.free(errPtr);
        s.cfRelease(attrs.cast());
      }
    } finally {
      s.cfRelease(sizeNum.cast());
      libcAlloc.free(sizePtr);
      libcAlloc.free(keysArr);
      libcAlloc.free(valsArr);
    }
  }

  @override
  Uint8List sign(Uint8List message) => _signRaw(_privateKeyRef, message, digest: false);

  @override
  Uint8List signDigest(Uint8List digest) => _signRaw(_privateKeyRef, digest, digest: true);

  static Uint8List _signRaw(SecKeyRef privateKey, Uint8List data, {required bool digest}) {
    final s = sec;
    final dataRef = s.bytesToCFData(data);
    final errPtr = libcAlloc.allocate<CFErrorRef>(1);
    errPtr.value = nullptr;
    try {
      final algorithm = digest
          ? s.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
          : s.kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
      final sigRef = s.secKeyCreateSignature(privateKey, algorithm, dataRef, errPtr);
      s.cfRelease(dataRef.cast());
      if (sigRef == nullptr) throw StateError('SecKeyCreateSignature failed');
      return s.cfDataToBytes(sigRef);
    } finally {
      libcAlloc.free(errPtr);
    }
  }

  @override
  void dispose() {
    _finalizer.detach(this);
    sec.cfRelease(_privateKeyRef.cast());
  }
}
