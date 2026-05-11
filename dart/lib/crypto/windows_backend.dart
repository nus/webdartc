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
import 'sha256.dart';
import 'x509_der.dart';

// ── AES-CM (AES-ECB single block) ──────────────────────────────────────────

final class WindowsAesCmBackend implements AesCmBackend {
  @override
  Uint8List aesEcbEncryptBlock(Uint8List key, Uint8List block) {
    assert(block.length == 16);
    final api = bcrypt;

    final keyPtr = calloc.allocate<Uint8>(key.length);
    final inPtr = calloc.allocate<Uint8>(16);
    final outPtr = calloc.allocate<Uint8>(16);
    final cbPtr = calloc<Uint32>();
    BCryptKeyHandle? hKey;
    try {
      for (var i = 0; i < key.length; i++) {
        keyPtr[i] = key[i];
      }
      for (var i = 0; i < 16; i++) {
        inPtr[i] = block[i];
      }
      hKey = api.generateSymmetricKey(api.aesEcb, keyPtr, key.length);
      final s = api.encrypt(
          hKey, inPtr, 16, nullptr, nullptr, 0, outPtr, 16, cbPtr, 0);
      if (!ntSuccess(s)) {
        throw StateError(
            'BCryptEncrypt(AES-ECB) failed: 0x${s.toRadixString(16)}');
      }
      final out = Uint8List(16);
      for (var i = 0; i < 16; i++) {
        out[i] = outPtr[i];
      }
      return out;
    } finally {
      if (hKey != null) api.destroyKey(hKey);
      calloc.free(keyPtr);
      calloc.free(inPtr);
      calloc.free(outPtr);
      calloc.free(cbPtr);
    }
  }
}

// ── AES-GCM ────────────────────────────────────────────────────────────────

final class WindowsAesGcmBackend implements AesGcmBackend {
  static const int _tagLength = 16;

  @override
  AesGcmResult encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext,
      Uint8List aad) {
    return _aesGcm(key, nonce, plaintext, aad, encrypt: true)!;
  }

  @override
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext,
      Uint8List expectedTag, Uint8List aad) {
    return _aesGcm(key, nonce, ciphertext, aad,
        encrypt: false, expectedTag: expectedTag)?.ciphertext;
  }

  /// Combined GCM encrypt/decrypt. For decrypt the return type's
  /// `ciphertext` field actually holds the recovered plaintext, and `tag`
  /// is irrelevant. Returns null on auth failure.
  AesGcmResult? _aesGcm(
    Uint8List key,
    Uint8List nonce,
    Uint8List data,
    Uint8List aad, {
    required bool encrypt,
    Uint8List? expectedTag,
  }) {
    final api = bcrypt;

    final keyPtr = calloc.allocate<Uint8>(key.length);
    final noncePtr = calloc.allocate<Uint8>(nonce.length);
    final aadPtr = aad.isEmpty ? nullptr : calloc.allocate<Uint8>(aad.length);
    final inPtr =
        data.isEmpty ? nullptr : calloc.allocate<Uint8>(data.length);
    final outPtr =
        data.isEmpty ? nullptr : calloc.allocate<Uint8>(data.length);
    final tagPtr = calloc.allocate<Uint8>(_tagLength);
    final infoPtr = calloc<BCryptAuthCipherModeInfo>();
    final cbPtr = calloc<Uint32>();
    BCryptKeyHandle? hKey;
    try {
      for (var i = 0; i < key.length; i++) {
        keyPtr[i] = key[i];
      }
      for (var i = 0; i < nonce.length; i++) {
        noncePtr[i] = nonce[i];
      }
      for (var i = 0; i < aad.length; i++) {
        aadPtr[i] = aad[i];
      }
      for (var i = 0; i < data.length; i++) {
        inPtr[i] = data[i];
      }
      if (!encrypt) {
        for (var i = 0; i < _tagLength; i++) {
          tagPtr[i] = expectedTag![i];
        }
      }

      final info = infoPtr.ref;
      info.cbSize = sizeOf<BCryptAuthCipherModeInfo>();
      info.dwInfoVersion = authModeInfoVersion;
      info.pbNonce = noncePtr;
      info.cbNonce = nonce.length;
      info.pbAuthData = aadPtr;
      info.cbAuthData = aad.length;
      info.pbTag = tagPtr;
      info.cbTag = _tagLength;
      info.pbMacContext = nullptr;
      info.cbMacContext = 0;
      info.cbAAD = 0;
      info.cbData = 0;
      info.dwFlags = 0;

      hKey = api.generateSymmetricKey(api.aesGcm, keyPtr, key.length);

      final int s;
      if (encrypt) {
        s = api.encrypt(hKey, inPtr, data.length, infoPtr.cast(), nullptr, 0,
            outPtr, data.length, cbPtr, 0);
        if (!ntSuccess(s)) {
          throw StateError(
              'BCryptEncrypt(AES-GCM) failed: 0x${s.toRadixString(16)}');
        }
      } else {
        s = api.decrypt(hKey, inPtr, data.length, infoPtr.cast(), nullptr, 0,
            outPtr, data.length, cbPtr, 0);
        // STATUS_AUTH_TAG_MISMATCH = 0xC000A002 (returned as negative int32).
        if (!ntSuccess(s)) return null;
      }

      final outData = Uint8List(data.length);
      for (var i = 0; i < data.length; i++) {
        outData[i] = outPtr[i];
      }
      final outTag = Uint8List(_tagLength);
      for (var i = 0; i < _tagLength; i++) {
        outTag[i] = tagPtr[i];
      }
      return AesGcmResult(ciphertext: outData, tag: outTag);
    } finally {
      if (hKey != null) api.destroyKey(hKey);
      calloc.free(keyPtr);
      calloc.free(noncePtr);
      if (aadPtr != nullptr) calloc.free(aadPtr);
      if (inPtr != nullptr) calloc.free(inPtr);
      if (outPtr != nullptr) calloc.free(outPtr);
      calloc.free(tagPtr);
      calloc.free(infoPtr);
      calloc.free(cbPtr);
    }
  }
}

// ── ChaCha20-Poly1305 ──────────────────────────────────────────────────────
//
// Windows 10 1903+ exposes CHACHA20_POLY1305 via CNG. On older builds the
// algorithm provider open fails; we then fall back to the pure-Dart
// implementation that the macOS backend also uses.

final class WindowsChaCha20Poly1305Backend implements ChaCha20Poly1305Backend {
  static const int _tagLength = 16;

  @override
  AeadResult encrypt(Uint8List key, Uint8List nonce, Uint8List plaintext,
      Uint8List aad) {
    final alg = bcrypt.chacha20Poly1305;
    if (alg == null) {
      final r = cc20p1305.aeadEncrypt(key, nonce, plaintext, aad);
      return AeadResult(ciphertext: r.ciphertext, tag: r.tag);
    }
    final r = _cng(key, nonce, plaintext, aad, alg: alg, encrypt: true)!;
    return AeadResult(ciphertext: r.ciphertext, tag: r.tag);
  }

  @override
  Uint8List? decrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext,
      Uint8List expectedTag, Uint8List aad) {
    final alg = bcrypt.chacha20Poly1305;
    if (alg == null) {
      return cc20p1305.aeadDecrypt(key, nonce, ciphertext, expectedTag, aad);
    }
    final r = _cng(key, nonce, ciphertext, aad,
        alg: alg, encrypt: false, expectedTag: expectedTag);
    return r?.ciphertext;
  }

  AesGcmResult? _cng(
    Uint8List key,
    Uint8List nonce,
    Uint8List data,
    Uint8List aad, {
    required BCryptAlgHandle alg,
    required bool encrypt,
    Uint8List? expectedTag,
  }) {
    final api = bcrypt;

    final keyPtr = calloc.allocate<Uint8>(key.length);
    final noncePtr = calloc.allocate<Uint8>(nonce.length);
    final aadPtr = aad.isEmpty ? nullptr : calloc.allocate<Uint8>(aad.length);
    final inPtr =
        data.isEmpty ? nullptr : calloc.allocate<Uint8>(data.length);
    final outPtr =
        data.isEmpty ? nullptr : calloc.allocate<Uint8>(data.length);
    final tagPtr = calloc.allocate<Uint8>(_tagLength);
    final infoPtr = calloc<BCryptAuthCipherModeInfo>();
    final cbPtr = calloc<Uint32>();
    BCryptKeyHandle? hKey;
    try {
      for (var i = 0; i < key.length; i++) {
        keyPtr[i] = key[i];
      }
      for (var i = 0; i < nonce.length; i++) {
        noncePtr[i] = nonce[i];
      }
      for (var i = 0; i < aad.length; i++) {
        aadPtr[i] = aad[i];
      }
      for (var i = 0; i < data.length; i++) {
        inPtr[i] = data[i];
      }
      if (!encrypt) {
        for (var i = 0; i < _tagLength; i++) {
          tagPtr[i] = expectedTag![i];
        }
      }

      final info = infoPtr.ref;
      info.cbSize = sizeOf<BCryptAuthCipherModeInfo>();
      info.dwInfoVersion = authModeInfoVersion;
      info.pbNonce = noncePtr;
      info.cbNonce = nonce.length;
      info.pbAuthData = aadPtr;
      info.cbAuthData = aad.length;
      info.pbTag = tagPtr;
      info.cbTag = _tagLength;
      info.pbMacContext = nullptr;
      info.cbMacContext = 0;
      info.cbAAD = 0;
      info.cbData = 0;
      info.dwFlags = 0;

      hKey = api.generateSymmetricKey(alg, keyPtr, key.length);

      final int s;
      if (encrypt) {
        s = api.encrypt(hKey, inPtr, data.length, infoPtr.cast(), nullptr, 0,
            outPtr, data.length, cbPtr, 0);
        if (!ntSuccess(s)) {
          throw StateError(
              'BCryptEncrypt(ChaCha20) failed: 0x${s.toRadixString(16)}');
        }
      } else {
        s = api.decrypt(hKey, inPtr, data.length, infoPtr.cast(), nullptr, 0,
            outPtr, data.length, cbPtr, 0);
        if (!ntSuccess(s)) return null;
      }

      final outData = Uint8List(data.length);
      for (var i = 0; i < data.length; i++) {
        outData[i] = outPtr[i];
      }
      final outTag = Uint8List(_tagLength);
      for (var i = 0; i < _tagLength; i++) {
        outTag[i] = tagPtr[i];
      }
      return AesGcmResult(ciphertext: outData, tag: outTag);
    } finally {
      if (hKey != null) api.destroyKey(hKey);
      calloc.free(keyPtr);
      calloc.free(noncePtr);
      if (aadPtr != nullptr) calloc.free(aadPtr);
      if (inPtr != nullptr) calloc.free(inPtr);
      if (outPtr != nullptr) calloc.free(outPtr);
      calloc.free(tagPtr);
      calloc.free(infoPtr);
      calloc.free(cbPtr);
    }
  }
}

// ── ECC blob helpers ────────────────────────────────────────────────────────
//
// BCRYPT_ECCKEY_BLOB header: dwMagic (4 bytes LE) + cbKey (4 bytes LE).
// Public P-256 blob: header(8) + X(32) + Y(32) = 72 bytes total.

/// Build an ECCPUBLICBLOB from a 65-byte uncompressed point (0x04 || X || Y).
/// Returns null when input is invalid.
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

/// Extract the uncompressed point (0x04 || X || Y) from an ECCPUBLICBLOB.
Uint8List _uncompressedFromEccPublicBlob(Uint8List blob) {
  // blob: 8 header + 32 X + 32 Y
  final out = Uint8List(65);
  out[0] = 0x04;
  out.setRange(1, 33, blob, 8);
  out.setRange(33, 65, blob, 40);
  return out;
}

// ── ECDH (P-256) ────────────────────────────────────────────────────────────

final class WindowsEcdhBackend implements EcdhBackend {
  final BCryptKeyHandle _priv;
  @override
  final Uint8List publicKeyBytes;
  bool _disposed = false;

  WindowsEcdhBackend._({required BCryptKeyHandle priv, required this.publicKeyBytes})
      : _priv = priv;

  factory WindowsEcdhBackend() {
    final api = bcrypt;
    final priv = api.generateKeyPair(api.ecdhP256, 256);
    final pubBlob = api.exportKey(priv, 'ECCPUBLICBLOB');
    final pubPoint = _uncompressedFromEccPublicBlob(pubBlob);
    return WindowsEcdhBackend._(priv: priv, publicKeyBytes: pubPoint);
  }

  @override
  Uint8List computeSharedSecret(Uint8List peerPublicKeyBytes) {
    final api = bcrypt;
    final blob = _eccPublicBlobFromUncompressed(
        peerPublicKeyBytes, ecdhPublicP256Magic);
    if (blob == null) throw StateError('Invalid peer public key bytes');

    final blobPtr = calloc.allocate<Uint8>(blob.length);
    try {
      for (var i = 0; i < blob.length; i++) {
        blobPtr[i] = blob[i];
      }
      final peerKey =
          api.importKeyPair(api.ecdhP256, 'ECCPUBLICBLOB', blobPtr, blob.length);
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
      calloc.free(blobPtr);
    }
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    bcrypt.destroyKey(_priv);
  }
}

// ── ECDSA signature DER codec ──────────────────────────────────────────────
//
// BCryptSignHash returns r||s (each 32 bytes for P-256). The X.509 spec
// wraps signatures as DER SEQUENCE { INTEGER r, INTEGER s } — same format
// OpenSSL and Apple's CryptoKit emit, so we encode/decode here.

Uint8List _rsToDer(Uint8List rs) {
  final n = rs.length ~/ 2;
  final r = Uint8List.sublistView(rs, 0, n);
  final s = Uint8List.sublistView(rs, n);
  final rDer = _intToDer(r);
  final sDer = _intToDer(s);
  final body = Uint8List(rDer.length + sDer.length);
  body.setRange(0, rDer.length, rDer);
  body.setRange(rDer.length, body.length, sDer);
  return _tlv(0x30, body);
}

Uint8List _intToDer(Uint8List bigEndian) {
  // Strip leading zeros, but keep one if the high bit of the first byte is
  // set (DER INTEGER is signed).
  var start = 0;
  while (start < bigEndian.length - 1 && bigEndian[start] == 0) {
    start++;
  }
  final body =
      bigEndian[start] & 0x80 != 0 ? Uint8List(bigEndian.length - start + 1) : Uint8List(bigEndian.length - start);
  if (bigEndian[start] & 0x80 != 0) {
    body[0] = 0x00;
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
/// Returns null on malformed input. Trims/zero-pads r and s to 32 bytes.
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
  // Strip leading zero added for sign bit (DER INTEGER may have one).
  var srcStart = 0;
  if (src.isNotEmpty && src[0] == 0x00 && src.length > size) {
    srcStart = 1;
  }
  final actual = src.length - srcStart;
  if (actual > size) return; // malformed — leave zeros
  final pad = size - actual;
  for (var i = 0; i < pad; i++) {
    dst[dstStart + i] = 0;
  }
  for (var i = 0; i < actual; i++) {
    dst[dstStart + pad + i] = src[srcStart + i];
  }
}

// ── ECDSA (P-256) ──────────────────────────────────────────────────────────

final class WindowsEcdsaBackend implements EcdsaBackend {
  @override
  final Uint8List derBytes;
  @override
  final String sha256Fingerprint;
  final BCryptKeyHandle _priv;
  bool _disposed = false;

  WindowsEcdsaBackend._({
    required this.derBytes,
    required this.sha256Fingerprint,
    required BCryptKeyHandle priv,
  }) : _priv = priv;

  factory WindowsEcdsaBackend() {
    final api = bcrypt;
    final priv = api.generateKeyPair(api.ecdsaP256, 256);
    final pubBlob = api.exportKey(priv, 'ECCPUBLICBLOB');
    final pubPoint = _uncompressedFromEccPublicBlob(pubBlob);

    final tbs = X509Der.buildTbsCertificate(pubPoint);
    final tbsHash = Sha256.hash(tbs);
    final rs = api.signHash(priv, tbsHash);
    final sigDer = _rsToDer(rs);
    final cert = X509Der.buildCertificate(tbs, sigDer);

    final fpBytes = Sha256.hash(cert);
    final fp = fpBytes
        .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
        .join(':');
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
    if (_disposed) return;
    _disposed = true;
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
    final digest = Sha256.hash(message);
    final api = bcrypt;

    final blob =
        _eccPublicBlobFromUncompressed(publicKey, ecdsaPublicP256Magic);
    if (blob == null) return false;

    final blobPtr = calloc.allocate<Uint8>(blob.length);
    try {
      for (var i = 0; i < blob.length; i++) {
        blobPtr[i] = blob[i];
      }
      final BCryptKeyHandle pubKey;
      try {
        pubKey = api.importKeyPair(
            api.ecdsaP256, 'ECCPUBLICBLOB', blobPtr, blob.length);
      } catch (_) {
        return false;
      }
      try {
        return api.verifySignature(pubKey, digest, rs);
      } finally {
        api.destroyKey(pubKey);
      }
    } finally {
      calloc.free(blobPtr);
    }
  }
}
