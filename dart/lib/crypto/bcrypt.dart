// Windows CNG (bcrypt.dll) FFI bindings.
//
// CNG is the post-Vista Windows cryptography API and is part of the OS —
// bcrypt.dll ships with every Windows installation, so no extra runtime
// dependency is required.
//
// All DynamicLibrary.open calls are behind lazy static fields so this file
// is safe to import on any platform; the library is only opened the first
// time a Windows backend is actually instantiated.
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// ── NTSTATUS ────────────────────────────────────────────────────────────────

const int statusSuccess = 0;
bool ntSuccess(int s) => s >= 0;

// ── BCrypt typedefs (all handles are PVOID) ─────────────────────────────────

typedef BCryptAlgHandle = Pointer<Void>;
typedef BCryptKeyHandle = Pointer<Void>;
typedef BCryptSecretHandle = Pointer<Void>;

// ── Native function signatures ──────────────────────────────────────────────

typedef _BCryptOpenAlgNative = Int32 Function(
    Pointer<Pointer<Void>>, Pointer<Uint16>, Pointer<Uint16>, Uint32);
typedef _BCryptOpenAlgDart = int Function(
    Pointer<Pointer<Void>>, Pointer<Uint16>, Pointer<Uint16>, int);

typedef _BCryptSetPropertyNative = Int32 Function(
    Pointer<Void>, Pointer<Uint16>, Pointer<Uint8>, Uint32, Uint32);
typedef _BCryptSetPropertyDart = int Function(
    Pointer<Void>, Pointer<Uint16>, Pointer<Uint8>, int, int);

typedef _BCryptGenerateSymKeyNative = Int32 Function(
    Pointer<Void>,
    Pointer<Pointer<Void>>,
    Pointer<Uint8>,
    Uint32,
    Pointer<Uint8>,
    Uint32,
    Uint32);
typedef _BCryptGenerateSymKeyDart = int Function(
    Pointer<Void>,
    Pointer<Pointer<Void>>,
    Pointer<Uint8>,
    int,
    Pointer<Uint8>,
    int,
    int);

typedef _BCryptDestroyKeyNative = Int32 Function(Pointer<Void>);
typedef _BCryptDestroyKeyDart = int Function(Pointer<Void>);

typedef _BCryptEncryptNative = Int32 Function(
    Pointer<Void>,        // hKey
    Pointer<Uint8>, Uint32, // pbInput, cbInput
    Pointer<Void>,        // pPaddingInfo
    Pointer<Uint8>, Uint32, // pbIV, cbIV
    Pointer<Uint8>, Uint32, // pbOutput, cbOutput
    Pointer<Uint32>,      // pcbResult
    Uint32);              // dwFlags
typedef _BCryptEncryptDart = int Function(
    Pointer<Void>,
    Pointer<Uint8>, int,
    Pointer<Void>,
    Pointer<Uint8>, int,
    Pointer<Uint8>, int,
    Pointer<Uint32>,
    int);

typedef _BCryptDecryptNative = _BCryptEncryptNative;
typedef _BCryptDecryptDart = _BCryptEncryptDart;

typedef _BCryptGenerateKeyPairNative = Int32 Function(
    Pointer<Void>, Pointer<Pointer<Void>>, Uint32, Uint32);
typedef _BCryptGenerateKeyPairDart = int Function(
    Pointer<Void>, Pointer<Pointer<Void>>, int, int);

typedef _BCryptFinalizeKeyPairNative = Int32 Function(Pointer<Void>, Uint32);
typedef _BCryptFinalizeKeyPairDart = int Function(Pointer<Void>, int);

typedef _BCryptExportKeyNative = Int32 Function(
    Pointer<Void>, // hKey
    Pointer<Void>, // hExportKey
    Pointer<Uint16>, // pszBlobType
    Pointer<Uint8>, Uint32, // pbOutput, cbOutput
    Pointer<Uint32>, // pcbResult
    Uint32); // dwFlags
typedef _BCryptExportKeyDart = int Function(
    Pointer<Void>,
    Pointer<Void>,
    Pointer<Uint16>,
    Pointer<Uint8>, int,
    Pointer<Uint32>,
    int);

typedef _BCryptImportKeyPairNative = Int32 Function(
    Pointer<Void>, // hAlgorithm
    Pointer<Void>, // hImportKey
    Pointer<Uint16>, // pszBlobType
    Pointer<Pointer<Void>>, // phKey
    Pointer<Uint8>, Uint32, // pbInput, cbInput
    Uint32); // dwFlags
typedef _BCryptImportKeyPairDart = int Function(
    Pointer<Void>,
    Pointer<Void>,
    Pointer<Uint16>,
    Pointer<Pointer<Void>>,
    Pointer<Uint8>, int,
    int);

typedef _BCryptSecretAgreementNative = Int32 Function(
    Pointer<Void>, Pointer<Void>, Pointer<Pointer<Void>>, Uint32);
typedef _BCryptSecretAgreementDart = int Function(
    Pointer<Void>, Pointer<Void>, Pointer<Pointer<Void>>, int);

typedef _BCryptDestroySecretNative = Int32 Function(Pointer<Void>);
typedef _BCryptDestroySecretDart = int Function(Pointer<Void>);

typedef _BCryptDeriveKeyNative = Int32 Function(
    Pointer<Void>, // hSharedSecret
    Pointer<Uint16>, // pwszKDF
    Pointer<Void>, // pParameterList
    Pointer<Uint8>, Uint32, // pbDerivedKey, cbDerivedKey
    Pointer<Uint32>, // pcbResult
    Uint32); // dwFlags
typedef _BCryptDeriveKeyDart = int Function(
    Pointer<Void>,
    Pointer<Uint16>,
    Pointer<Void>,
    Pointer<Uint8>, int,
    Pointer<Uint32>,
    int);

typedef _BCryptSignHashNative = Int32 Function(
    Pointer<Void>, // hKey
    Pointer<Void>, // pPaddingInfo
    Pointer<Uint8>, Uint32, // pbInput, cbInput
    Pointer<Uint8>, Uint32, // pbOutput, cbOutput
    Pointer<Uint32>, // pcbResult
    Uint32); // dwFlags
typedef _BCryptSignHashDart = int Function(
    Pointer<Void>,
    Pointer<Void>,
    Pointer<Uint8>, int,
    Pointer<Uint8>, int,
    Pointer<Uint32>,
    int);

typedef _BCryptVerifySignatureNative = Int32 Function(
    Pointer<Void>, // hKey
    Pointer<Void>, // pPaddingInfo
    Pointer<Uint8>, Uint32, // pbHash, cbHash
    Pointer<Uint8>, Uint32, // pbSignature, cbSignature
    Uint32); // dwFlags
typedef _BCryptVerifySignatureDart = int Function(
    Pointer<Void>,
    Pointer<Void>,
    Pointer<Uint8>, int,
    Pointer<Uint8>, int,
    int);

// ── BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO struct ────────────────────────────
//
// Layout matches Windows SDK <bcrypt.h>. On x64 the natural alignment puts
// ULONG fields next to PUCHAR fields with 4-byte padding gaps. Dart FFI
// computes the same layout automatically when we declare pointers as
// 8-byte and ULONGs as 4-byte.

// Dart FFI applies natural alignment to struct fields (matching the C ABI),
// so 4-byte padding gaps between ULONG and PUCHAR on x64 are inserted
// automatically — no explicit padding fields needed. Expected sizeof on x64
// is 88 bytes (also what Windows SDK reports).
final class BCryptAuthCipherModeInfo extends Struct {
  @Uint32() external int cbSize;
  @Uint32() external int dwInfoVersion;
  external Pointer<Uint8> pbNonce;
  @Uint32() external int cbNonce;
  external Pointer<Uint8> pbAuthData;
  @Uint32() external int cbAuthData;
  external Pointer<Uint8> pbTag;
  @Uint32() external int cbTag;
  external Pointer<Uint8> pbMacContext;
  @Uint32() external int cbMacContext;
  @Uint32() external int cbAAD;
  @Uint64() external int cbData;
  @Uint32() external int dwFlags;
}

const int authModeInfoVersion = 1;

// ── BCrypt constants ────────────────────────────────────────────────────────

const int ecdhPublicP256Magic = 0x314B4345; // 'ECK1'
const int ecdhPrivateP256Magic = 0x324B4345; // 'ECK2'
const int ecdsaPublicP256Magic = 0x31534345; // 'ECS1'
const int ecdsaPrivateP256Magic = 0x32534345; // 'ECS2'

// ── Wide-string helper ──────────────────────────────────────────────────────

/// Allocate a null-terminated UTF-16LE string in native memory.
/// Caller must `calloc.free` the returned pointer.
Pointer<Uint16> wideString(String s) {
  final units = s.codeUnits;
  final ptr = calloc.allocate<Uint16>((units.length + 1) * 2);
  for (var i = 0; i < units.length; i++) {
    ptr[i] = units[i];
  }
  ptr[units.length] = 0;
  return ptr;
}

// ── BCrypt API singleton ────────────────────────────────────────────────────

final class BCryptApi {
  static final BCryptApi instance = BCryptApi._();
  BCryptApi._();

  static final DynamicLibrary _lib = DynamicLibrary.open('bcrypt.dll');

  final _open = _lib.lookupFunction<_BCryptOpenAlgNative, _BCryptOpenAlgDart>(
      'BCryptOpenAlgorithmProvider');
  // BCryptCloseAlgorithmProvider exists but algorithm provider handles are
  // process-lifetime cached, so we never close them. Binding omitted.
  final _setProp = _lib.lookupFunction<_BCryptSetPropertyNative,
      _BCryptSetPropertyDart>('BCryptSetProperty');
  final _genSym = _lib.lookupFunction<_BCryptGenerateSymKeyNative,
      _BCryptGenerateSymKeyDart>('BCryptGenerateSymmetricKey');
  final _destroyKey = _lib
      .lookupFunction<_BCryptDestroyKeyNative, _BCryptDestroyKeyDart>(
          'BCryptDestroyKey');
  final _encrypt = _lib
      .lookupFunction<_BCryptEncryptNative, _BCryptEncryptDart>('BCryptEncrypt');
  final _decrypt = _lib
      .lookupFunction<_BCryptDecryptNative, _BCryptDecryptDart>('BCryptDecrypt');
  final _genKp = _lib.lookupFunction<_BCryptGenerateKeyPairNative,
      _BCryptGenerateKeyPairDart>('BCryptGenerateKeyPair');
  final _finalKp = _lib.lookupFunction<_BCryptFinalizeKeyPairNative,
      _BCryptFinalizeKeyPairDart>('BCryptFinalizeKeyPair');
  final _exportKey = _lib
      .lookupFunction<_BCryptExportKeyNative, _BCryptExportKeyDart>(
          'BCryptExportKey');
  final _importKp = _lib.lookupFunction<_BCryptImportKeyPairNative,
      _BCryptImportKeyPairDart>('BCryptImportKeyPair');
  final _agree = _lib.lookupFunction<_BCryptSecretAgreementNative,
      _BCryptSecretAgreementDart>('BCryptSecretAgreement');
  final _destroySecret = _lib.lookupFunction<_BCryptDestroySecretNative,
      _BCryptDestroySecretDart>('BCryptDestroySecret');
  final _derive = _lib.lookupFunction<_BCryptDeriveKeyNative,
      _BCryptDeriveKeyDart>('BCryptDeriveKey');
  final _sign = _lib
      .lookupFunction<_BCryptSignHashNative, _BCryptSignHashDart>('BCryptSignHash');
  final _verify = _lib.lookupFunction<_BCryptVerifySignatureNative,
      _BCryptVerifySignatureDart>('BCryptVerifySignature');

  // ── Lazy algorithm provider handles ───────────────────────────────────────
  //
  // Each provider is opened once and cached for the process lifetime.
  // For block ciphers we open one handle per chaining mode because the
  // chaining mode is a property of the algorithm handle, not the key.

  late final BCryptAlgHandle _aesEcb = _openAlgWithMode('AES', 'ChainingModeECB');
  late final BCryptAlgHandle _aesGcm = _openAlgWithMode('AES', 'ChainingModeGCM');
  late final BCryptAlgHandle? _chacha20 = _tryOpenAlg('CHACHA20_POLY1305');
  late final BCryptAlgHandle _ecdhP256 = _openAlg('ECDH_P256');
  late final BCryptAlgHandle _ecdsaP256 = _openAlg('ECDSA_P256');

  BCryptAlgHandle get aesEcb => _aesEcb;
  BCryptAlgHandle get aesGcm => _aesGcm;
  BCryptAlgHandle? get chacha20Poly1305 => _chacha20;
  BCryptAlgHandle get ecdhP256 => _ecdhP256;
  BCryptAlgHandle get ecdsaP256 => _ecdsaP256;

  BCryptAlgHandle _openAlg(String algId) {
    final algPtr = wideString(algId);
    final hPtr = calloc<Pointer<Void>>();
    try {
      final s = _open(hPtr, algPtr, nullptr, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptOpenAlgorithmProvider($algId) failed: 0x${s.toRadixString(16)}');
      }
      return hPtr.value;
    } finally {
      calloc.free(algPtr);
      calloc.free(hPtr);
    }
  }

  BCryptAlgHandle? _tryOpenAlg(String algId) {
    final algPtr = wideString(algId);
    final hPtr = calloc<Pointer<Void>>();
    try {
      final s = _open(hPtr, algPtr, nullptr, 0);
      if (!ntSuccess(s)) return null;
      return hPtr.value;
    } finally {
      calloc.free(algPtr);
      calloc.free(hPtr);
    }
  }

  BCryptAlgHandle _openAlgWithMode(String algId, String mode) {
    final h = _openAlg(algId);
    final propPtr = wideString('ChainingMode');
    final modePtr = wideString(mode);
    final modeBytes = (mode.length + 1) * 2;
    try {
      final s = _setProp(h, propPtr, modePtr.cast(), modeBytes, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptSetProperty(ChainingMode=$mode) failed: 0x${s.toRadixString(16)}');
      }
      return h;
    } finally {
      calloc.free(propPtr);
      calloc.free(modePtr);
    }
  }

  // ── Public wrappers ───────────────────────────────────────────────────────

  BCryptKeyHandle generateSymmetricKey(
      BCryptAlgHandle alg, Pointer<Uint8> keyBytes, int keyLen) {
    final hPtr = calloc<Pointer<Void>>();
    try {
      final s = _genSym(alg, hPtr, nullptr, 0, keyBytes, keyLen, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptGenerateSymmetricKey failed: 0x${s.toRadixString(16)}');
      }
      return hPtr.value;
    } finally {
      calloc.free(hPtr);
    }
  }

  int destroyKey(BCryptKeyHandle hKey) => _destroyKey(hKey);

  int encrypt(
    BCryptKeyHandle hKey,
    Pointer<Uint8> pbInput, int cbInput,
    Pointer<Void> pPaddingInfo,
    Pointer<Uint8> pbIV, int cbIV,
    Pointer<Uint8> pbOutput, int cbOutput,
    Pointer<Uint32> pcbResult,
    int dwFlags,
  ) => _encrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV,
        pbOutput, cbOutput, pcbResult, dwFlags);

  int decrypt(
    BCryptKeyHandle hKey,
    Pointer<Uint8> pbInput, int cbInput,
    Pointer<Void> pPaddingInfo,
    Pointer<Uint8> pbIV, int cbIV,
    Pointer<Uint8> pbOutput, int cbOutput,
    Pointer<Uint32> pcbResult,
    int dwFlags,
  ) => _decrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV,
        pbOutput, cbOutput, pcbResult, dwFlags);

  BCryptKeyHandle generateKeyPair(BCryptAlgHandle alg, int bits) {
    final hPtr = calloc<Pointer<Void>>();
    try {
      final s = _genKp(alg, hPtr, bits, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptGenerateKeyPair failed: 0x${s.toRadixString(16)}');
      }
      final k = hPtr.value;
      final s2 = _finalKp(k, 0);
      if (!ntSuccess(s2)) {
        _destroyKey(k);
        throw StateError(
            'BCryptFinalizeKeyPair failed: 0x${s2.toRadixString(16)}');
      }
      return k;
    } finally {
      calloc.free(hPtr);
    }
  }

  /// Export key in [blobType]. Returns a fresh Uint8List copy.
  Uint8List exportKey(BCryptKeyHandle hKey, String blobType) {
    final btPtr = wideString(blobType);
    final cbPtr = calloc<Uint32>();
    try {
      var s = _exportKey(hKey, nullptr, btPtr, nullptr, 0, cbPtr, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptExportKey(size $blobType) failed: 0x${s.toRadixString(16)}');
      }
      final size = cbPtr.value;
      final buf = calloc.allocate<Uint8>(size);
      try {
        s = _exportKey(hKey, nullptr, btPtr, buf, size, cbPtr, 0);
        if (!ntSuccess(s)) {
          throw StateError(
              'BCryptExportKey($blobType) failed: 0x${s.toRadixString(16)}');
        }
        final out = Uint8List(size);
        for (var i = 0; i < size; i++) {
          out[i] = buf[i];
        }
        return out;
      } finally {
        calloc.free(buf);
      }
    } finally {
      calloc.free(btPtr);
      calloc.free(cbPtr);
    }
  }

  BCryptKeyHandle importKeyPair(
      BCryptAlgHandle alg, String blobType, Pointer<Uint8> data, int dataLen) {
    final btPtr = wideString(blobType);
    final hPtr = calloc<Pointer<Void>>();
    try {
      final s = _importKp(alg, nullptr, btPtr, hPtr, data, dataLen, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptImportKeyPair($blobType) failed: 0x${s.toRadixString(16)}');
      }
      return hPtr.value;
    } finally {
      calloc.free(btPtr);
      calloc.free(hPtr);
    }
  }

  BCryptSecretHandle secretAgreement(
      BCryptKeyHandle priv, BCryptKeyHandle pub) {
    final hPtr = calloc<Pointer<Void>>();
    try {
      final s = _agree(priv, pub, hPtr, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptSecretAgreement failed: 0x${s.toRadixString(16)}');
      }
      return hPtr.value;
    } finally {
      calloc.free(hPtr);
    }
  }

  int destroySecret(BCryptSecretHandle h) => _destroySecret(h);

  Uint8List deriveRawSecret(BCryptSecretHandle secret, int length) {
    final kdfPtr = wideString('TRUNCATE');
    final cbPtr = calloc<Uint32>();
    final buf = calloc.allocate<Uint8>(length);
    try {
      cbPtr.value = 0;
      final s =
          _derive(secret, kdfPtr, nullptr, buf, length, cbPtr, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptDeriveKey(TRUNCATE) failed: 0x${s.toRadixString(16)}');
      }
      final got = cbPtr.value;
      // BCryptDeriveKey with BCRYPT_KDF_RAW_SECRET returns the X coordinate
      // in little-endian byte order; reverse to standard big-endian.
      final out = Uint8List(got);
      for (var i = 0; i < got; i++) {
        out[i] = buf[got - 1 - i];
      }
      return out;
    } finally {
      calloc.free(kdfPtr);
      calloc.free(cbPtr);
      calloc.free(buf);
    }
  }

  /// Sign a pre-computed hash. Returns the raw concatenated r||s
  /// (32 + 32 = 64 bytes for ECDSA-P256). Caller is responsible for
  /// converting to DER if needed.
  Uint8List signHash(BCryptKeyHandle hKey, Uint8List digest) {
    final inBuf = calloc.allocate<Uint8>(digest.length);
    final cbPtr = calloc<Uint32>();
    try {
      for (var i = 0; i < digest.length; i++) {
        inBuf[i] = digest[i];
      }
      cbPtr.value = 0;
      var s = _sign(hKey, nullptr, inBuf, digest.length, nullptr, 0, cbPtr, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptSignHash(size) failed: 0x${s.toRadixString(16)}');
      }
      final size = cbPtr.value;
      final outBuf = calloc.allocate<Uint8>(size);
      try {
        s = _sign(hKey, nullptr, inBuf, digest.length, outBuf, size, cbPtr, 0);
        if (!ntSuccess(s)) {
          throw StateError(
              'BCryptSignHash failed: 0x${s.toRadixString(16)}');
        }
        final got = cbPtr.value;
        final out = Uint8List(got);
        for (var i = 0; i < got; i++) {
          out[i] = outBuf[i];
        }
        return out;
      } finally {
        calloc.free(outBuf);
      }
    } finally {
      calloc.free(inBuf);
      calloc.free(cbPtr);
    }
  }

  /// Verify a raw r||s signature against a pre-computed hash.
  bool verifySignature(
      BCryptKeyHandle hKey, Uint8List digest, Uint8List rawSig) {
    final hashBuf = calloc.allocate<Uint8>(digest.length);
    final sigBuf = calloc.allocate<Uint8>(rawSig.length);
    try {
      for (var i = 0; i < digest.length; i++) {
        hashBuf[i] = digest[i];
      }
      for (var i = 0; i < rawSig.length; i++) {
        sigBuf[i] = rawSig[i];
      }
      final s = _verify(
          hKey, nullptr, hashBuf, digest.length, sigBuf, rawSig.length, 0);
      return ntSuccess(s);
    } finally {
      calloc.free(hashBuf);
      calloc.free(sigBuf);
    }
  }
}

// Convenience accessor.
BCryptApi get bcrypt => BCryptApi.instance;
