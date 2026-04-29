// Package-private FFI bindings for OpenSSL libcrypto on Linux.
// Do NOT import this file from outside lib/crypto/.
import 'dart:ffi';

// ── OpenSSL constants ───────────────────────────────────────────────────────

const int _evpCtrlGcmSetIvlen = 0x09;
const int _evpCtrlGcmGetTag = 0x10;
const int _evpCtrlGcmSetTag = 0x11;
const int _nidX9_62Prime256v1 = 415; // NID_X9_62_prime256v1
const int _pointConversionUncompressed = 4;

// ── Native function type aliases ────────────────────────────────────────────

// EVP_CIPHER_CTX
typedef _EvpCipherCtxNewN = Pointer<Void> Function();
typedef _EvpCipherCtxFreeN = Void Function(Pointer<Void>);
typedef _EvpCipherCtxFreeD = void Function(Pointer<Void>);
typedef _EvpCipherCtxCtrlN = Int32 Function(Pointer<Void>, Int32, Int32, Pointer<Void>);
typedef _EvpCipherCtxCtrlD = int Function(Pointer<Void>, int, int, Pointer<Void>);

// EVP_Encrypt / EVP_Decrypt
typedef _EvpEncryptInitExN = Int32 Function(
    Pointer<Void>, Pointer<Void>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EvpEncryptInitExD = int Function(
    Pointer<Void>, Pointer<Void>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EvpEncryptUpdateN = Int32 Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, Int32);
typedef _EvpEncryptUpdateD = int Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int);
typedef _EvpEncryptFinalExN = Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Int32>);
typedef _EvpEncryptFinalExD = int Function(Pointer<Void>, Pointer<Uint8>, Pointer<Int32>);

typedef _EvpDecryptInitExN = Int32 Function(
    Pointer<Void>, Pointer<Void>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EvpDecryptInitExD = int Function(
    Pointer<Void>, Pointer<Void>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>);
typedef _EvpDecryptUpdateN = Int32 Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, Int32);
typedef _EvpDecryptUpdateD = int Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, int);
typedef _EvpDecryptFinalExN = Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Int32>);
typedef _EvpDecryptFinalExD = int Function(Pointer<Void>, Pointer<Uint8>, Pointer<Int32>);

// EVP_CIPHER getters (return const EVP_CIPHER*)
typedef _EvpCipherN = Pointer<Void> Function();

// EC_KEY
typedef _EcKeyNewByCurveNameN = Pointer<Void> Function(Int32);
typedef _EcKeyNewByCurveNameD = Pointer<Void> Function(int);
typedef _EcKeyGenerateKeyN = Int32 Function(Pointer<Void>);
typedef _EcKeyGenerateKeyD = int Function(Pointer<Void>);
typedef _EcKeyFreeN = Void Function(Pointer<Void>);
typedef _EcKeyFreeD = void Function(Pointer<Void>);
typedef _EcKeyGet0PublicKeyN = Pointer<Void> Function(Pointer<Void>);
typedef _EcKeyGet0PrivateKeyN = Pointer<Void> Function(Pointer<Void>);
typedef _EcKeyGet0GroupN = Pointer<Void> Function(Pointer<Void>);

// EC_POINT
typedef _EcPointPoint2OctN = Size Function(
    Pointer<Void>, Pointer<Void>, Int32, Pointer<Uint8>, Size, Pointer<Void>);
typedef _EcPointPoint2OctD = int Function(
    Pointer<Void>, Pointer<Void>, int, Pointer<Uint8>, int, Pointer<Void>);
typedef _EcPointOct2PointN = Pointer<Void> Function(
    Pointer<Void>, Pointer<Void>, Pointer<Uint8>, Size, Pointer<Void>);
typedef _EcPointOct2PointD = Pointer<Void> Function(
    Pointer<Void>, Pointer<Void>, Pointer<Uint8>, int, Pointer<Void>);
typedef _EcPointNewN = Pointer<Void> Function(Pointer<Void>);
typedef _EcPointFreeN = Void Function(Pointer<Void>);
typedef _EcPointFreeD = void Function(Pointer<Void>);

// ECDH
typedef _EcdhComputeKeyN = Int32 Function(
    Pointer<Uint8>, Int32, Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef _EcdhComputeKeyD = int Function(
    Pointer<Uint8>, int, Pointer<Void>, Pointer<Void>, Pointer<Void>);

// ECDSA
typedef _EcdsaSignN = Int32 Function(
    Int32, Pointer<Uint8>, Int32, Pointer<Uint8>, Pointer<Uint32>, Pointer<Void>);
typedef _EcdsaSignD = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint32>, Pointer<Void>);
typedef _EcdsaSizeN = Int32 Function(Pointer<Void>);
typedef _EcdsaSizeD = int Function(Pointer<Void>);
typedef _EcdsaVerifyN = Int32 Function(
    Int32, Pointer<Uint8>, Int32, Pointer<Uint8>, Int32, Pointer<Void>);
typedef _EcdsaVerifyD = int Function(
    int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Void>);
typedef _EcKeySetPublicKeyN = Int32 Function(Pointer<Void>, Pointer<Void>);
typedef _EcKeySetPublicKeyD = int Function(Pointer<Void>, Pointer<Void>);

// EVP_MD_CTX / EVP_DigestSign (for message signing without pre-hashing)
typedef _EvpMdCtxNewN = Pointer<Void> Function();
typedef _EvpMdCtxFreeN = Void Function(Pointer<Void>);
typedef _EvpMdCtxFreeD = void Function(Pointer<Void>);
typedef _EvpDigestSignInitN = Int32 Function(
    Pointer<Void>, Pointer<Pointer<Void>>, Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef _EvpDigestSignInitD = int Function(
    Pointer<Void>, Pointer<Pointer<Void>>, Pointer<Void>, Pointer<Void>, Pointer<Void>);
typedef _EvpDigestSignN = Int32 Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Size>, Pointer<Uint8>, Size);
typedef _EvpDigestSignD = int Function(
    Pointer<Void>, Pointer<Uint8>, Pointer<Size>, Pointer<Uint8>, int);

// EVP_PKEY
typedef _EvpPkeyNewN = Pointer<Void> Function();
typedef _EvpPkeyFreeN = Void Function(Pointer<Void>);
typedef _EvpPkeyFreeD = void Function(Pointer<Void>);
// EVP_sha256
typedef _EvpSha256N = Pointer<Void> Function();

// ── Singleton bindings ──────────────────────────────────────────────────────

class OpenSsl {
  OpenSsl._();

  static final OpenSsl instance = OpenSsl._();

  static DynamicLibrary _loadLibcrypto() {
    for (final name in ['libcrypto.so', 'libcrypto.so.3', 'libcrypto.so.1.1']) {
      try {
        return DynamicLibrary.open(name);
      } on ArgumentError {
        continue;
      }
    }
    throw UnsupportedError('Could not load OpenSSL libcrypto. '
        'Tried: libcrypto.so, libcrypto.so.3, libcrypto.so.1.1');
  }

  late final DynamicLibrary lib = _loadLibcrypto();

  // EVP_CIPHER_CTX
  late final evpCipherCtxNew = lib.lookupFunction<_EvpCipherCtxNewN, Pointer<Void> Function()>('EVP_CIPHER_CTX_new');
  late final evpCipherCtxFree = lib.lookupFunction<_EvpCipherCtxFreeN, _EvpCipherCtxFreeD>('EVP_CIPHER_CTX_free');
  late final evpCipherCtxCtrl = lib.lookupFunction<_EvpCipherCtxCtrlN, _EvpCipherCtxCtrlD>('EVP_CIPHER_CTX_ctrl');

  // EVP_Encrypt
  late final evpEncryptInitEx = lib.lookupFunction<_EvpEncryptInitExN, _EvpEncryptInitExD>('EVP_EncryptInit_ex');
  late final evpEncryptUpdate = lib.lookupFunction<_EvpEncryptUpdateN, _EvpEncryptUpdateD>('EVP_EncryptUpdate');
  late final evpEncryptFinalEx = lib.lookupFunction<_EvpEncryptFinalExN, _EvpEncryptFinalExD>('EVP_EncryptFinal_ex');

  // EVP_Decrypt
  late final evpDecryptInitEx = lib.lookupFunction<_EvpDecryptInitExN, _EvpDecryptInitExD>('EVP_DecryptInit_ex');
  late final evpDecryptUpdate = lib.lookupFunction<_EvpDecryptUpdateN, _EvpDecryptUpdateD>('EVP_DecryptUpdate');
  late final evpDecryptFinalEx = lib.lookupFunction<_EvpDecryptFinalExN, _EvpDecryptFinalExD>('EVP_DecryptFinal_ex');

  // EVP cipher algorithms
  late final evpAes128Ecb = lib.lookupFunction<_EvpCipherN, Pointer<Void> Function()>('EVP_aes_128_ecb');
  late final evpAes256Ecb = lib.lookupFunction<_EvpCipherN, Pointer<Void> Function()>('EVP_aes_256_ecb');
  late final evpAes128Gcm = lib.lookupFunction<_EvpCipherN, Pointer<Void> Function()>('EVP_aes_128_gcm');
  late final evpAes256Gcm = lib.lookupFunction<_EvpCipherN, Pointer<Void> Function()>('EVP_aes_256_gcm');
  late final evpChaCha20Poly1305 = lib.lookupFunction<_EvpCipherN, Pointer<Void> Function()>('EVP_chacha20_poly1305');

  // EC_KEY
  late final ecKeyNewByCurveName = lib.lookupFunction<_EcKeyNewByCurveNameN, _EcKeyNewByCurveNameD>('EC_KEY_new_by_curve_name');
  late final ecKeyGenerateKey = lib.lookupFunction<_EcKeyGenerateKeyN, _EcKeyGenerateKeyD>('EC_KEY_generate_key');
  late final ecKeyFree = lib.lookupFunction<_EcKeyFreeN, _EcKeyFreeD>('EC_KEY_free');
  late final ecKeyGet0PublicKey = lib.lookupFunction<_EcKeyGet0PublicKeyN, Pointer<Void> Function(Pointer<Void>)>('EC_KEY_get0_public_key');
  late final ecKeyGet0PrivateKey = lib.lookupFunction<_EcKeyGet0PrivateKeyN, Pointer<Void> Function(Pointer<Void>)>('EC_KEY_get0_private_key');
  late final ecKeyGet0Group = lib.lookupFunction<_EcKeyGet0GroupN, Pointer<Void> Function(Pointer<Void>)>('EC_KEY_get0_group');

  // EC_POINT
  late final ecPointPoint2Oct = lib.lookupFunction<_EcPointPoint2OctN, _EcPointPoint2OctD>('EC_POINT_point2oct');
  late final ecPointOct2Point = lib.lookupFunction<_EcPointOct2PointN, _EcPointOct2PointD>('EC_POINT_oct2point');
  late final ecPointNew = lib.lookupFunction<_EcPointNewN, Pointer<Void> Function(Pointer<Void>)>('EC_POINT_new');
  late final ecPointFree = lib.lookupFunction<_EcPointFreeN, _EcPointFreeD>('EC_POINT_free');

  // ECDH
  late final ecdhComputeKey = lib.lookupFunction<_EcdhComputeKeyN, _EcdhComputeKeyD>('ECDH_compute_key');

  // ECDSA
  late final ecdsaSign = lib.lookupFunction<_EcdsaSignN, _EcdsaSignD>('ECDSA_sign');
  late final ecdsaSize = lib.lookupFunction<_EcdsaSizeN, _EcdsaSizeD>('ECDSA_size');
  late final ecdsaVerify = lib.lookupFunction<_EcdsaVerifyN, _EcdsaVerifyD>('ECDSA_verify');
  late final ecKeySetPublicKey = lib.lookupFunction<_EcKeySetPublicKeyN, _EcKeySetPublicKeyD>('EC_KEY_set_public_key');

  // EVP_MD_CTX (for DigestSign)
  late final evpMdCtxNew = lib.lookupFunction<_EvpMdCtxNewN, Pointer<Void> Function()>('EVP_MD_CTX_new');
  late final evpMdCtxFree = lib.lookupFunction<_EvpMdCtxFreeN, _EvpMdCtxFreeD>('EVP_MD_CTX_free');
  late final evpDigestSignInit = lib.lookupFunction<_EvpDigestSignInitN, _EvpDigestSignInitD>('EVP_DigestSignInit');
  late final evpDigestSign = lib.lookupFunction<_EvpDigestSignN, _EvpDigestSignD>('EVP_DigestSign');

  // EVP_PKEY
  late final evpPkeyNew = lib.lookupFunction<_EvpPkeyNewN, Pointer<Void> Function()>('EVP_PKEY_new');
  late final evpPkeyFree = lib.lookupFunction<_EvpPkeyFreeN, _EvpPkeyFreeD>('EVP_PKEY_free');
  // EVP_PKEY_assign_EC_KEY is a macro in headers, but exists as a function:
  late final evpPkeySet1EcKey = lib.lookupFunction<
      Int32 Function(Pointer<Void>, Pointer<Void>),
      int Function(Pointer<Void>, Pointer<Void>)>('EVP_PKEY_set1_EC_KEY');

  late final evpSha256 = lib.lookupFunction<_EvpSha256N, Pointer<Void> Function()>('EVP_sha256');

  // EVP_PKEY_get1_EC_KEY — returns EC_KEY* with incremented refcount
  late final evpPkeyGet1EcKey = lib.lookupFunction<
      Pointer<Void> Function(Pointer<Void>),
      Pointer<Void> Function(Pointer<Void>)>('EVP_PKEY_get1_EC_KEY');

  // NativeFinalizer target for EVP_PKEY_free
  late final evpPkeyFreePtr = lib.lookup<NativeFunction<Void Function(Pointer<Void>)>>('EVP_PKEY_free');

  // Constants
  int get nidP256 => _nidX9_62Prime256v1;
  int get pointConversionUncompressed => _pointConversionUncompressed;
  int get evpCtrlGcmSetIvlen => _evpCtrlGcmSetIvlen;
  int get evpCtrlGcmGetTag => _evpCtrlGcmGetTag;
  int get evpCtrlGcmSetTag => _evpCtrlGcmSetTag;
}

final ossl = OpenSsl.instance;
