// Package-private FFI bindings for BoringSSL libcrypto, used by the Linux +
// Android crypto backend (boringssl_backend.dart).
//
// BoringSSL is statically linked into the bundled `webdartc_crypto` library by
// dart/hook/build.dart, which exports only the `wd_*` passthrough wrappers
// declared in dart/src/webdartc_crypto.{h,c}. These `@Native` bindings resolve
// those wrappers against that bundled asset. The library is only built on
// Linux + Android, and the functions are only ever called there (the crypto
// factory selects this backend only on those platforms), so the declarations
// are inert on macOS / Windows.
//
// Do NOT import this file from outside lib/crypto/.
@DefaultAsset('package:webdartc/crypto/webdartc_crypto.dart')
library;

import 'dart:ffi';

// ── BoringSSL constants ─────────────────────────────────────────────────────

const int _evpCtrlGcmSetIvlen = 0x09;
const int _evpCtrlGcmGetTag = 0x10;
const int _evpCtrlGcmSetTag = 0x11;
const int _nidX9_62Prime256v1 = 415; // NID_X9_62_prime256v1
const int _pointConversionUncompressed = 4;

// ── @Native wrapper bindings (wd_* exported by webdartc_crypto) ──────────────

// EVP_CIPHER_CTX
@Native<Pointer<Void> Function()>(symbol: 'wd_EVP_CIPHER_CTX_new')
external Pointer<Void> _evpCipherCtxNew();
@Native<Void Function(Pointer<Void>)>(symbol: 'wd_EVP_CIPHER_CTX_free')
external void _evpCipherCtxFree(Pointer<Void> ctx);
@Native<Int32 Function(Pointer<Void>, Int32, Int32, Pointer<Void>)>(
    symbol: 'wd_EVP_CIPHER_CTX_ctrl')
external int _evpCipherCtxCtrl(Pointer<Void> ctx, int type, int arg, Pointer<Void> ptr);

// EVP_Encrypt
@Native<Int32 Function(Pointer<Void>, Pointer<Void>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>)>(
    symbol: 'wd_EVP_EncryptInit_ex')
external int _evpEncryptInitEx(Pointer<Void> ctx, Pointer<Void> cipher, Pointer<Void> impl, Pointer<Uint8> key, Pointer<Uint8> iv);
@Native<Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, Int32)>(
    symbol: 'wd_EVP_EncryptUpdate')
external int _evpEncryptUpdate(Pointer<Void> ctx, Pointer<Uint8> out, Pointer<Int32> outl, Pointer<Uint8> inp, int inl);
@Native<Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Int32>)>(
    symbol: 'wd_EVP_EncryptFinal_ex')
external int _evpEncryptFinalEx(Pointer<Void> ctx, Pointer<Uint8> out, Pointer<Int32> outl);

// EVP_Decrypt
@Native<Int32 Function(Pointer<Void>, Pointer<Void>, Pointer<Void>, Pointer<Uint8>, Pointer<Uint8>)>(
    symbol: 'wd_EVP_DecryptInit_ex')
external int _evpDecryptInitEx(Pointer<Void> ctx, Pointer<Void> cipher, Pointer<Void> impl, Pointer<Uint8> key, Pointer<Uint8> iv);
@Native<Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Int32>, Pointer<Uint8>, Int32)>(
    symbol: 'wd_EVP_DecryptUpdate')
external int _evpDecryptUpdate(Pointer<Void> ctx, Pointer<Uint8> out, Pointer<Int32> outl, Pointer<Uint8> inp, int inl);
@Native<Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Int32>)>(
    symbol: 'wd_EVP_DecryptFinal_ex')
external int _evpDecryptFinalEx(Pointer<Void> ctx, Pointer<Uint8> out, Pointer<Int32> outl);

// EVP_CIPHER getters
@Native<Pointer<Void> Function()>(symbol: 'wd_EVP_aes_128_ecb')
external Pointer<Void> _evpAes128Ecb();
@Native<Pointer<Void> Function()>(symbol: 'wd_EVP_aes_256_ecb')
external Pointer<Void> _evpAes256Ecb();
@Native<Pointer<Void> Function()>(symbol: 'wd_EVP_aes_128_gcm')
external Pointer<Void> _evpAes128Gcm();
@Native<Pointer<Void> Function()>(symbol: 'wd_EVP_aes_256_gcm')
external Pointer<Void> _evpAes256Gcm();

// EC_KEY
@Native<Pointer<Void> Function(Int32)>(symbol: 'wd_EC_KEY_new_by_curve_name')
external Pointer<Void> _ecKeyNewByCurveName(int nid);
@Native<Int32 Function(Pointer<Void>)>(symbol: 'wd_EC_KEY_generate_key')
external int _ecKeyGenerateKey(Pointer<Void> key);
@Native<Void Function(Pointer<Void>)>(symbol: 'wd_EC_KEY_free')
external void _ecKeyFree(Pointer<Void> key);
@Native<Pointer<Void> Function(Pointer<Void>)>(symbol: 'wd_EC_KEY_get0_public_key')
external Pointer<Void> _ecKeyGet0PublicKey(Pointer<Void> key);
@Native<Pointer<Void> Function(Pointer<Void>)>(symbol: 'wd_EC_KEY_get0_private_key')
external Pointer<Void> _ecKeyGet0PrivateKey(Pointer<Void> key);
@Native<Pointer<Void> Function(Pointer<Void>)>(symbol: 'wd_EC_KEY_get0_group')
external Pointer<Void> _ecKeyGet0Group(Pointer<Void> key);
@Native<Int32 Function(Pointer<Void>, Pointer<Void>)>(symbol: 'wd_EC_KEY_set_public_key')
external int _ecKeySetPublicKey(Pointer<Void> key, Pointer<Void> point);

// EC_POINT
@Native<Size Function(Pointer<Void>, Pointer<Void>, Int32, Pointer<Uint8>, Size, Pointer<Void>)>(
    symbol: 'wd_EC_POINT_point2oct')
external int _ecPointPoint2Oct(Pointer<Void> group, Pointer<Void> point, int form, Pointer<Uint8> buf, int len, Pointer<Void> ctx);
@Native<Pointer<Void> Function(Pointer<Void>, Pointer<Void>, Pointer<Uint8>, Size, Pointer<Void>)>(
    symbol: 'wd_EC_POINT_oct2point')
external Pointer<Void> _ecPointOct2Point(Pointer<Void> group, Pointer<Void> point, Pointer<Uint8> buf, int len, Pointer<Void> ctx);
@Native<Pointer<Void> Function(Pointer<Void>)>(symbol: 'wd_EC_POINT_new')
external Pointer<Void> _ecPointNew(Pointer<Void> group);
@Native<Void Function(Pointer<Void>)>(symbol: 'wd_EC_POINT_free')
external void _ecPointFree(Pointer<Void> point);

// ECDH
@Native<Int32 Function(Pointer<Uint8>, Int32, Pointer<Void>, Pointer<Void>, Pointer<Void>)>(
    symbol: 'wd_ECDH_compute_key')
external int _ecdhComputeKey(Pointer<Uint8> out, int outlen, Pointer<Void> pub, Pointer<Void> ecdh, Pointer<Void> kdf);

// ECDSA
@Native<Int32 Function(Int32, Pointer<Uint8>, Int32, Pointer<Uint8>, Pointer<Uint32>, Pointer<Void>)>(
    symbol: 'wd_ECDSA_sign')
external int _ecdsaSign(int type, Pointer<Uint8> dgst, int dgstlen, Pointer<Uint8> sig, Pointer<Uint32> siglen, Pointer<Void> eckey);
@Native<Int32 Function(Pointer<Void>)>(symbol: 'wd_ECDSA_size')
external int _ecdsaSize(Pointer<Void> eckey);
@Native<Int32 Function(Int32, Pointer<Uint8>, Int32, Pointer<Uint8>, Int32, Pointer<Void>)>(
    symbol: 'wd_ECDSA_verify')
external int _ecdsaVerify(int type, Pointer<Uint8> dgst, int dgstlen, Pointer<Uint8> sig, int siglen, Pointer<Void> eckey);

// EVP_MD_CTX / EVP_DigestSign
@Native<Pointer<Void> Function()>(symbol: 'wd_EVP_MD_CTX_new')
external Pointer<Void> _evpMdCtxNew();
@Native<Void Function(Pointer<Void>)>(symbol: 'wd_EVP_MD_CTX_free')
external void _evpMdCtxFree(Pointer<Void> ctx);
@Native<Int32 Function(Pointer<Void>, Pointer<Pointer<Void>>, Pointer<Void>, Pointer<Void>, Pointer<Void>)>(
    symbol: 'wd_EVP_DigestSignInit')
external int _evpDigestSignInit(Pointer<Void> ctx, Pointer<Pointer<Void>> pctx, Pointer<Void> type, Pointer<Void> impl, Pointer<Void> pkey);
@Native<Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Size>, Pointer<Uint8>, Size)>(
    symbol: 'wd_EVP_DigestSign')
external int _evpDigestSign(Pointer<Void> ctx, Pointer<Uint8> sig, Pointer<Size> siglen, Pointer<Uint8> tbs, int tbslen);

// EVP_PKEY
@Native<Pointer<Void> Function()>(symbol: 'wd_EVP_PKEY_new')
external Pointer<Void> _evpPkeyNew();
@Native<Void Function(Pointer<Void>)>(symbol: 'wd_EVP_PKEY_free')
external void _evpPkeyFree(Pointer<Void> pkey);
@Native<Int32 Function(Pointer<Void>, Pointer<Void>)>(symbol: 'wd_EVP_PKEY_set1_EC_KEY')
external int _evpPkeySet1EcKey(Pointer<Void> pkey, Pointer<Void> key);
@Native<Pointer<Void> Function(Pointer<Void>)>(symbol: 'wd_EVP_PKEY_get1_EC_KEY')
external Pointer<Void> _evpPkeyGet1EcKey(Pointer<Void> pkey);
@Native<Pointer<Void> Function()>(symbol: 'wd_EVP_sha256')
external Pointer<Void> _evpSha256();

// ── Facade ──────────────────────────────────────────────────────────────────
//
// Field names match the previous OpenSSL binding so boringssl_backend.dart is
// unchanged. Each field is a tear-off of the corresponding `@Native` function.

class OpenSsl {
  OpenSsl._();
  static final OpenSsl instance = OpenSsl._();

  final evpCipherCtxNew = _evpCipherCtxNew;
  final evpCipherCtxFree = _evpCipherCtxFree;
  final evpCipherCtxCtrl = _evpCipherCtxCtrl;

  final evpEncryptInitEx = _evpEncryptInitEx;
  final evpEncryptUpdate = _evpEncryptUpdate;
  final evpEncryptFinalEx = _evpEncryptFinalEx;

  final evpDecryptInitEx = _evpDecryptInitEx;
  final evpDecryptUpdate = _evpDecryptUpdate;
  final evpDecryptFinalEx = _evpDecryptFinalEx;

  final evpAes128Ecb = _evpAes128Ecb;
  final evpAes256Ecb = _evpAes256Ecb;
  final evpAes128Gcm = _evpAes128Gcm;
  final evpAes256Gcm = _evpAes256Gcm;

  final ecKeyNewByCurveName = _ecKeyNewByCurveName;
  final ecKeyGenerateKey = _ecKeyGenerateKey;
  final ecKeyFree = _ecKeyFree;
  final ecKeyGet0PublicKey = _ecKeyGet0PublicKey;
  final ecKeyGet0PrivateKey = _ecKeyGet0PrivateKey;
  final ecKeyGet0Group = _ecKeyGet0Group;
  final ecKeySetPublicKey = _ecKeySetPublicKey;

  final ecPointPoint2Oct = _ecPointPoint2Oct;
  final ecPointOct2Point = _ecPointOct2Point;
  final ecPointNew = _ecPointNew;
  final ecPointFree = _ecPointFree;

  final ecdhComputeKey = _ecdhComputeKey;

  final ecdsaSign = _ecdsaSign;
  final ecdsaSize = _ecdsaSize;
  final ecdsaVerify = _ecdsaVerify;

  final evpMdCtxNew = _evpMdCtxNew;
  final evpMdCtxFree = _evpMdCtxFree;
  final evpDigestSignInit = _evpDigestSignInit;
  final evpDigestSign = _evpDigestSign;

  final evpPkeyNew = _evpPkeyNew;
  final evpPkeyFree = _evpPkeyFree;
  final evpPkeySet1EcKey = _evpPkeySet1EcKey;
  final evpPkeyGet1EcKey = _evpPkeyGet1EcKey;
  final evpSha256 = _evpSha256;

  // NativeFinalizer targets (function pointers).
  final evpPkeyFreePtr =
      Native.addressOf<NativeFunction<Void Function(Pointer<Void>)>>(
          _evpPkeyFree);
  final ecKeyFreePtr =
      Native.addressOf<NativeFunction<Void Function(Pointer<Void>)>>(
          _ecKeyFree);

  // Constants
  int get nidP256 => _nidX9_62Prime256v1;
  int get pointConversionUncompressed => _pointConversionUncompressed;
  int get evpCtrlGcmSetIvlen => _evpCtrlGcmSetIvlen;
  int get evpCtrlGcmGetTag => _evpCtrlGcmGetTag;
  int get evpCtrlGcmSetTag => _evpCtrlGcmSetTag;
}

final ossl = OpenSsl.instance;
