// Windows crypto backend using CNG (bcrypt.dll).
//
// bcrypt.dll ships with Windows; no extra install needed. All DynamicLibrary
// lookups are lazy via [BCryptApi], so this file is safe to import on any
// platform — it only resolves symbols when a Windows backend is actually
// instantiated.
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'aes_gcm.dart' show AesGcmResult;
import 'bcrypt.dart';
import 'chacha20_poly1305.dart' show AeadResult;
import 'chacha20_poly1305_pure.dart' as cc20p1305;
import 'crypto_backend.dart';
import 'native_alloc.dart' show toNative, fromNative;
import 'sha256.dart';
import 'x509_der.dart';

Pointer<Uint8> _toNativeOrNull(Uint8List src, Allocator alloc) =>
    src.isEmpty ? nullptr : toNative(src, alloc);

// ── AES-CM (AES-ECB single block) ──────────────────────────────────────────

final class WindowsAesCmBackend implements AesCmBackend {
  @override
  Uint8List aesEcbEncryptBlock(Uint8List key, Uint8List block) {
    assert(block.length == 16);
    final api = bcrypt;

    final keyPtr = toNative(key, malloc);
    final inPtr = toNative(block, malloc);
    final outPtr = malloc.allocate<Uint8>(16);
    final cbPtr = malloc<Uint32>();
    BCryptKeyHandle? hKey;
    try {
      hKey = api.generateSymmetricKey(api.aesEcb, keyPtr, key.length);
      final s = api.encrypt(
          hKey, inPtr, 16, nullptr, nullptr, 0, outPtr, 16, cbPtr, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptEncrypt(AES-ECB) failed: 0x${s.toRadixString(16)}');
      }
      return fromNative(outPtr, 16);
    } finally {
      if (hKey != null) api.destroyKey(hKey);
      malloc.free(keyPtr);
      malloc.free(inPtr);
      malloc.free(outPtr);
      malloc.free(cbPtr);
    }
  }
}

// ── AEAD (AES-GCM and ChaCha20-Poly1305) shared core ───────────────────────
//
// BCryptEncrypt/Decrypt use exactly the same call sequence for any cipher
// configured with BCRYPT_CHAIN_MODE_GCM or for CNG's CHACHA20_POLY1305
// algorithm — only the algorithm handle and the error label differ.

const int _aeadTagLength = 16;

({Uint8List ciphertext, Uint8List tag})? _aeadEncryptDecrypt({
  required BCryptAlgHandle alg,
  required Uint8List key,
  required Uint8List nonce,
  required Uint8List data,
  required Uint8List aad,
  required bool encrypt,
  Uint8List? expectedTag,
  required String label,
}) {
  final api = bcrypt;

  final keyPtr = toNative(key, malloc);
  final noncePtr = toNative(nonce, malloc);
  final aadPtr = _toNativeOrNull(aad, malloc);
  final inPtr = _toNativeOrNull(data, malloc);
  final outPtr =
      data.isEmpty ? nullptr : malloc.allocate<Uint8>(data.length);
  // For encrypt: tagPtr is the output buffer.
  // For decrypt: BCryptDecrypt verifies pbTag against the computed MAC, so it
  // must contain the *expected* tag on entry.
  final tagPtr = encrypt
      ? malloc.allocate<Uint8>(_aeadTagLength)
      : toNative(expectedTag!, malloc);
  // Zero-init: dwFlags / cbAAD / cbData / cbMacContext stay 0 for single-shot.
  final infoPtr = calloc<BCryptAuthCipherModeInfo>();
  final cbPtr = malloc<Uint32>();
  BCryptKeyHandle? hKey;
  try {
    final info = infoPtr.ref;
    info.cbSize = sizeOf<BCryptAuthCipherModeInfo>();
    info.dwInfoVersion = authModeInfoVersion;
    info.pbNonce = noncePtr;
    info.cbNonce = nonce.length;
    info.pbAuthData = aadPtr;
    info.cbAuthData = aad.length;
    info.pbTag = tagPtr;
    info.cbTag = _aeadTagLength;

    hKey = api.generateSymmetricKey(alg, keyPtr, key.length);

    final s = encrypt
        ? api.encrypt(hKey, inPtr, data.length, infoPtr.cast(), nullptr, 0,
            outPtr, data.length, cbPtr, 0)
        : api.decrypt(hKey, inPtr, data.length, infoPtr.cast(), nullptr, 0,
            outPtr, data.length, cbPtr, 0);
    if (!ntSuccess(s)) {
      // STATUS_AUTH_TAG_MISMATCH (0xC000A002) and other AEAD failures come
      // back negative; treat as authentication failure on decrypt.
      if (!encrypt) return null;
      throw StateError('BCrypt $label failed: 0x${s.toRadixString(16)}');
    }

    return (
      ciphertext: fromNative(outPtr, data.length),
      tag: fromNative(tagPtr, _aeadTagLength),
    );
  } finally {
    if (hKey != null) api.destroyKey(hKey);
    malloc.free(keyPtr);
    malloc.free(noncePtr);
    malloc.free(aadPtr);
    malloc.free(inPtr);
    malloc.free(outPtr);
    malloc.free(tagPtr);
    calloc.free(infoPtr);
    malloc.free(cbPtr);
  }
}

// ── AES-GCM ────────────────────────────────────────────────────────────────

final class WindowsAesGcmBackend implements AesGcmBackend {
  @override
  AesGcmResult encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext,
      Uint8List aad) {
    final r = _aeadEncryptDecrypt(
      alg: bcrypt.aesGcm,
      key: key,
      nonce: nonce,
      data: plaintext,
      aad: aad,
      encrypt: true,
      label: 'AES-GCM',
    )!;
    return AesGcmResult(ciphertext: r.ciphertext, tag: r.tag);
  }

  @override
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext,
      Uint8List expectedTag, Uint8List aad) {
    return _aeadEncryptDecrypt(
      alg: bcrypt.aesGcm,
      key: key,
      nonce: nonce,
      data: ciphertext,
      aad: aad,
      encrypt: false,
      expectedTag: expectedTag,
      label: 'AES-GCM',
    )?.ciphertext;
  }
}

// ── ChaCha20-Poly1305 ──────────────────────────────────────────────────────
//
// CNG's CHACHA20_POLY1305 algorithm requires Windows 10 1903+. On older
// builds the provider open returns null and we fall back to the pure-Dart
// RFC 8439 implementation (same path the macOS backend uses).

final class WindowsChaCha20Poly1305Backend implements ChaCha20Poly1305Backend {
  @override
  AeadResult encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext,
      Uint8List aad) {
    final alg = bcrypt.chacha20Poly1305;
    if (alg == null) {
      final r = cc20p1305.aeadEncrypt(key, nonce, plaintext, aad);
      return AeadResult(ciphertext: r.ciphertext, tag: r.tag);
    }
    final r = _aeadEncryptDecrypt(
      alg: alg,
      key: key,
      nonce: nonce,
      data: plaintext,
      aad: aad,
      encrypt: true,
      label: 'ChaCha20-Poly1305',
    )!;
    return AeadResult(ciphertext: r.ciphertext, tag: r.tag);
  }

  @override
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext,
      Uint8List expectedTag, Uint8List aad) {
    final alg = bcrypt.chacha20Poly1305;
    if (alg == null) {
      return cc20p1305.aeadDecrypt(key, nonce, ciphertext, expectedTag, aad);
    }
    return _aeadEncryptDecrypt(
      alg: alg,
      key: key,
      nonce: nonce,
      data: ciphertext,
      aad: aad,
      encrypt: false,
      expectedTag: expectedTag,
      label: 'ChaCha20-Poly1305',
    )?.ciphertext;
  }
}

// ── ECC blob helpers ────────────────────────────────────────────────────────
//
// BCRYPT_ECCKEY_BLOB header: dwMagic (4 bytes LE) + cbKey (4 bytes LE).
// Public P-256 blob: header(8) + X(32) + Y(32) = 72 bytes total.

Uint8List? _eccPublicBlobFromUncompressed(Uint8List point, int magic) {
  if (point.length != 65 || point[0] != 0x04) return null;
  final blob = Uint8List(72);
  final bd = ByteData.view(blob.buffer);
  bd.setUint32(0, magic, Endian.little);
  bd.setUint32(4, 32, Endian.little);
  blob.setRange(8, 40, point, 1); // X
  blob.setRange(40, 72, point, 33); // Y
  return blob;
}

Uint8List _uncompressedFromEccPublicBlob(Uint8List blob) {
  final out = Uint8List(65);
  out[0] = 0x04;
  out.setRange(1, 33, blob, 8);
  out.setRange(33, 65, blob, 40);
  return out;
}

// ── ECDH (P-256) ────────────────────────────────────────────────────────────

final class WindowsEcdhBackend implements EcdhBackend, Finalizable {
  static final _finalizer = NativeFinalizer(BCryptApi.destroyKeyFinalizer);

  final BCryptKeyHandle _priv;
  @override
  final Uint8List publicKeyBytes;

  WindowsEcdhBackend._(
      {required BCryptKeyHandle priv, required this.publicKeyBytes})
      : _priv = priv {
    _finalizer.attach(this, _priv, detach: this);
  }

  factory WindowsEcdhBackend() {
    final api = bcrypt;
    final priv = api.generateKeyPair(api.ecdhP256, 256);
    final pubBlob = api.exportKey(priv, blobEccPublic);
    final pubPoint = _uncompressedFromEccPublicBlob(pubBlob);
    return WindowsEcdhBackend._(priv: priv, publicKeyBytes: pubPoint);
  }

  @override
  Uint8List computeSharedSecret(Uint8List peerPublicKeyBytes) {
    final api = bcrypt;
    final blob = _eccPublicBlobFromUncompressed(
        peerPublicKeyBytes, ecdhPublicP256Magic);
    if (blob == null) throw StateError('Invalid peer public key bytes');

    final blobPtr = toNative(blob, malloc);
    try {
      final peerKey =
          api.importKeyPair(api.ecdhP256, blobEccPublic, blobPtr, blob.length);
      try {
        final secret = api.secretAgreement(_priv, peerKey);
        try {
          return api.deriveRawSecret(secret, 32);
        } finally {
          api.destroySecret(secret);
        }
      } finally {
        api.destroyKey(peerKey);
      }
    } finally {
      malloc.free(blobPtr);
    }
  }

  @override
  void dispose() {
    _finalizer.detach(this);
    bcrypt.destroyKey(_priv);
  }
}

// ── ECDSA signature DER codec ──────────────────────────────────────────────
//
// BCryptSignHash returns r||s (each 32 bytes for P-256). The X.509 spec
// wraps signatures as DER SEQUENCE { INTEGER r, INTEGER s } — the format
// OpenSSL and Apple's CryptoKit emit, so callers expect DER.

Uint8List _rsToDer(Uint8List rs) {
  final n = rs.length ~/ 2;
  final rDer = _intToDer(Uint8List.sublistView(rs, 0, n));
  final sDer = _intToDer(Uint8List.sublistView(rs, n));
  final body = Uint8List(rDer.length + sDer.length);
  body.setRange(0, rDer.length, rDer);
  body.setRange(rDer.length, body.length, sDer);
  return _tlv(0x30, body);
}

Uint8List _intToDer(Uint8List bigEndian) {
  var start = 0;
  while (start < bigEndian.length - 1 && bigEndian[start] == 0) {
    start++;
  }
  // DER INTEGER is signed: prepend 0x00 if the high bit of the leading byte
  // would otherwise make the value negative.
  final needSignByte = bigEndian[start] & 0x80 != 0;
  final body = Uint8List(bigEndian.length - start + (needSignByte ? 1 : 0));
  if (needSignByte) {
    body.setRange(1, body.length, bigEndian, start);
  } else {
    body.setRange(0, body.length, bigEndian, start);
  }
  return _tlv(0x02, body);
}

Uint8List _tlv(int tag, Uint8List value) {
  final lenBytes = _derLen(value.length);
  final out = Uint8List(1 + lenBytes.length + value.length);
  out[0] = tag;
  out.setRange(1, 1 + lenBytes.length, lenBytes);
  out.setRange(1 + lenBytes.length, out.length, value);
  return out;
}

Uint8List _derLen(int len) {
  if (len < 128) return Uint8List.fromList([len]);
  if (len < 256) return Uint8List.fromList([0x81, len]);
  return Uint8List.fromList([0x82, len >> 8, len & 0xff]);
}

/// Parse DER `SEQUENCE { INTEGER r, INTEGER s }` into a 64-byte r||s buffer.
/// Returns null on malformed input.
Uint8List? _derToRs(Uint8List der) {
  var off = 0;
  if (off >= der.length || der[off++] != 0x30) return null;
  final seqLen = _readLen(der, off);
  if (seqLen == null) return null;
  off = seqLen.next;
  final seqEnd = off + seqLen.value;
  if (seqEnd > der.length) return null;

  if (off >= seqEnd || der[off++] != 0x02) return null;
  final rLen = _readLen(der, off);
  if (rLen == null) return null;
  off = rLen.next;
  if (off + rLen.value > seqEnd) return null;
  final r = Uint8List.sublistView(der, off, off + rLen.value);
  off += rLen.value;

  if (off >= seqEnd || der[off++] != 0x02) return null;
  final sLen = _readLen(der, off);
  if (sLen == null) return null;
  off = sLen.next;
  if (off + sLen.value > seqEnd) return null;
  final s = Uint8List.sublistView(der, off, off + sLen.value);

  final rs = Uint8List(64);
  _copyPadded(r, rs, 0, 32);
  _copyPadded(s, rs, 32, 32);
  return rs;
}

class _Len {
  final int value;
  final int next;
  _Len(this.value, this.next);
}

_Len? _readLen(Uint8List buf, int off) {
  if (off >= buf.length) return null;
  final b = buf[off];
  if (b < 0x80) return _Len(b, off + 1);
  final n = b & 0x7f;
  if (n == 0 || n > 4) return null;
  if (off + 1 + n > buf.length) return null;
  var v = 0;
  for (var i = 0; i < n; i++) {
    v = (v << 8) | buf[off + 1 + i];
  }
  return _Len(v, off + 1 + n);
}

void _copyPadded(Uint8List src, Uint8List dst, int dstStart, int size) {
  // DER INTEGER may carry a leading 0x00 for sign — strip it when present.
  var srcStart = 0;
  if (src.isNotEmpty && src[0] == 0x00 && src.length > size) {
    srcStart = 1;
  }
  final actual = src.length - srcStart;
  if (actual > size) return; // malformed — leave zeros
  final pad = size - actual;
  for (var i = 0; i < actual; i++) {
    dst[dstStart + pad + i] = src[srcStart + i];
  }
}

// ── ECDSA (P-256) ──────────────────────────────────────────────────────────

final class WindowsEcdsaBackend implements EcdsaBackend, Finalizable {
  static final _finalizer = NativeFinalizer(BCryptApi.destroyKeyFinalizer);

  @override
  final Uint8List derBytes;
  @override
  final String sha256Fingerprint;
  final BCryptKeyHandle _priv;

  WindowsEcdsaBackend._({
    required this.derBytes,
    required this.sha256Fingerprint,
    required BCryptKeyHandle priv,
  }) : _priv = priv {
    _finalizer.attach(this, _priv, detach: this);
  }

  factory WindowsEcdsaBackend() {
    final api = bcrypt;
    final priv = api.generateKeyPair(api.ecdsaP256, 256);
    final pubBlob = api.exportKey(priv, blobEccPublic);
    final pubPoint = _uncompressedFromEccPublicBlob(pubBlob);

    final tbs = X509Der.buildTbsCertificate(pubPoint);
    final sigDer = _rsToDer(api.signHash(priv, Sha256.hash(tbs)));
    final cert = X509Der.buildCertificate(tbs, sigDer);

    final fp = Sha256.fingerprint(cert);
    return WindowsEcdsaBackend._(
        derBytes: cert, sha256Fingerprint: fp, priv: priv);
  }

  @override
  Uint8List sign(Uint8List message) =>
      _rsToDer(bcrypt.signHash(_priv, Sha256.hash(message)));

  @override
  Uint8List signDigest(Uint8List digest) =>
      _rsToDer(bcrypt.signHash(_priv, digest));

  @override
  void dispose() {
    _finalizer.detach(this);
    bcrypt.destroyKey(_priv);
  }
}

// ── ECDSA verify (stateless) ────────────────────────────────────────────────

final class WindowsEcdsaVerifyBackend implements EcdsaVerifyBackend {
  @override
  bool verifyP256Sha256({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    if (publicKey.length != 65 || publicKey[0] != 0x04) return false;
    final rs = _derToRs(signature);
    if (rs == null) return false;
    final blob =
        _eccPublicBlobFromUncompressed(publicKey, ecdsaPublicP256Magic);
    if (blob == null) return false;

    final api = bcrypt;
    final digest = Sha256.hash(message);
    final blobPtr = toNative(blob, malloc);
    try {
      final BCryptKeyHandle pubKey;
      try {
        pubKey =
            api.importKeyPair(api.ecdsaP256, blobEccPublic, blobPtr, blob.length);
      } catch (_) {
        return false;
      }
      try {
        return api.verifySignature(pubKey, digest, rs);
      } finally {
        api.destroyKey(pubKey);
      }
    } finally {
      malloc.free(blobPtr);
    }
  }
}
