// Pure-Dart ChaCha20-Poly1305 AEAD per RFC 8439.
//
// Used as the macOS backend for [ChaCha20Poly1305] because CommonCrypto
// does not expose ChaCha20 / Poly1305 and CryptoKit is Swift-only. The
// implementation follows the RFC pseudocode literally and is **not**
// constant-time — see the warning on [ChaCha20Poly1305].
//
// All arithmetic is performed in 32-bit lanes via `& 0xFFFFFFFF` masks
// to stay within Dart's signed-int semantics on the web (and remain
// correct on the VM).
import 'dart:typed_data';

const int _mask32 = 0xFFFFFFFF;

// ── ChaCha20 block function (RFC 8439 §2.3) ────────────────────────────────

int _rotl32(int x, int n) =>
    ((x << n) & _mask32) | ((x & _mask32) >>> (32 - n));

void _quarterRound(Uint32List s, int a, int b, int c, int d) {
  // a += b; d ^= a; d <<<= 16;
  s[a] = (s[a] + s[b]) & _mask32;
  s[d] = _rotl32(s[d] ^ s[a], 16);
  // c += d; b ^= c; b <<<= 12;
  s[c] = (s[c] + s[d]) & _mask32;
  s[b] = _rotl32(s[b] ^ s[c], 12);
  // a += b; d ^= a; d <<<= 8;
  s[a] = (s[a] + s[b]) & _mask32;
  s[d] = _rotl32(s[d] ^ s[a], 8);
  // c += d; b ^= c; b <<<= 7;
  s[c] = (s[c] + s[d]) & _mask32;
  s[b] = _rotl32(s[b] ^ s[c], 7);
}

/// Produce one 64-byte ChaCha20 keystream block.
///
/// [key]   : 32 bytes
/// [nonce] : 12 bytes
/// [counter] : 32-bit block counter (RFC 8439 §2.3 starts from 1 for
///   AEAD encryption; block 0 is reserved for Poly1305 key derivation).
Uint8List chacha20Block(Uint8List key, int counter, Uint8List nonce) {
  assert(key.length == 32);
  assert(nonce.length == 12);

  final state = Uint32List(16);
  // "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;

  // Key in little-endian 32-bit words.
  final kbd = ByteData.sublistView(key);
  for (var i = 0; i < 8; i++) {
    state[4 + i] = kbd.getUint32(i * 4, Endian.little);
  }
  state[12] = counter & _mask32;
  final nbd = ByteData.sublistView(nonce);
  state[13] = nbd.getUint32(0, Endian.little);
  state[14] = nbd.getUint32(4, Endian.little);
  state[15] = nbd.getUint32(8, Endian.little);

  final working = Uint32List.fromList(state);
  for (var i = 0; i < 10; i++) {
    // Column rounds
    _quarterRound(working, 0, 4, 8, 12);
    _quarterRound(working, 1, 5, 9, 13);
    _quarterRound(working, 2, 6, 10, 14);
    _quarterRound(working, 3, 7, 11, 15);
    // Diagonal rounds
    _quarterRound(working, 0, 5, 10, 15);
    _quarterRound(working, 1, 6, 11, 12);
    _quarterRound(working, 2, 7, 8, 13);
    _quarterRound(working, 3, 4, 9, 14);
  }

  final out = Uint8List(64);
  final obd = ByteData.sublistView(out);
  for (var i = 0; i < 16; i++) {
    obd.setUint32(i * 4, (working[i] + state[i]) & _mask32, Endian.little);
  }
  return out;
}

/// ChaCha20 stream cipher (RFC 8439 §2.4). Encrypts/decrypts [data] —
/// the operation is symmetric.
Uint8List chacha20Xor(
    Uint8List key, int initialCounter, Uint8List nonce, Uint8List data) {
  final out = Uint8List(data.length);
  var counter = initialCounter;
  var off = 0;
  while (off < data.length) {
    final block = chacha20Block(key, counter, nonce);
    final n = (data.length - off) < 64 ? data.length - off : 64;
    for (var i = 0; i < n; i++) {
      out[off + i] = data[off + i] ^ block[i];
    }
    off += n;
    counter = (counter + 1) & _mask32;
  }
  return out;
}

// ── Poly1305 (RFC 8439 §2.5) ────────────────────────────────────────────────

/// Compute Poly1305(key, msg) -> 16-byte tag.
///
/// [key] is the 32-byte one-time Poly1305 key (the `r||s` pair).
Uint8List poly1305Mac(Uint8List key, Uint8List msg) {
  assert(key.length == 32);

  // r is the first 16 bytes, clamped per RFC 8439 §2.5. s is the next 16.
  // Use BigInt arithmetic — clean and correct, if not blazing fast.
  final r = BigInt.parse(_hex(_clampR(key.sublist(0, 16))), radix: 16);
  final s = BigInt.parse(_hex(_reverseBytes(key.sublist(16, 32))), radix: 16);
  // Note: _reverseBytes converts little-endian bytes to a hex string usable
  // with BigInt.parse (which expects big-endian hex).

  final p =
      BigInt.parse('3fffffffffffffffffffffffffffffffb', radix: 16); // 2^130 − 5

  var acc = BigInt.zero;
  var off = 0;
  while (off < msg.length) {
    final blockLen = (msg.length - off) < 16 ? msg.length - off : 16;
    // Treat block as a little-endian integer with a high "1" byte appended.
    final block = Uint8List(blockLen + 1);
    for (var i = 0; i < blockLen; i++) {
      block[i] = msg[off + i];
    }
    block[blockLen] = 0x01;
    final n = BigInt.parse(_hex(_reverseBytes(block)), radix: 16);
    acc = ((acc + n) * r) % p;
    off += blockLen;
  }

  acc = (acc + s) & ((BigInt.one << 128) - BigInt.one);

  // Serialize as little-endian 16 bytes.
  final tag = Uint8List(16);
  var v = acc;
  for (var i = 0; i < 16; i++) {
    tag[i] = (v & BigInt.from(0xFF)).toInt();
    v = v >> 8;
  }
  return tag;
}

Uint8List _clampR(Uint8List r) {
  final out = Uint8List.fromList(r);
  out[3] &= 15;
  out[7] &= 15;
  out[11] &= 15;
  out[15] &= 15;
  out[4] &= 252;
  out[8] &= 252;
  out[12] &= 252;
  // After clamping, reverse for big-endian hex (BigInt.parse).
  return _reverseBytes(out);
}

Uint8List _reverseBytes(Uint8List src) {
  final out = Uint8List(src.length);
  for (var i = 0; i < src.length; i++) {
    out[i] = src[src.length - 1 - i];
  }
  return out;
}

String _hex(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

// ── AEAD construction (RFC 8439 §2.8) ──────────────────────────────────────

/// Derive the per-message Poly1305 key from the AEAD key and nonce.
/// RFC 8439 §2.6: keystream block 0 — the first 32 bytes are the
/// Poly1305 one-time key.
Uint8List poly1305KeyGen(Uint8List key, Uint8List nonce) {
  final block = chacha20Block(key, 0, nonce);
  return Uint8List.sublistView(block, 0, 32);
}

/// AEAD encrypt: returns (ciphertext, tag) per RFC 8439 §2.8.1.
({Uint8List ciphertext, Uint8List tag}) aeadEncrypt(
    Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
  final otk = poly1305KeyGen(key, nonce);
  final ciphertext = chacha20Xor(key, 1, nonce, plaintext);

  final macData = _macInput(aad, ciphertext);
  final tag = poly1305Mac(otk, macData);
  return (ciphertext: ciphertext, tag: tag);
}

/// AEAD decrypt: returns plaintext on success, null on tag mismatch.
Uint8List? aeadDecrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext,
    Uint8List expectedTag, Uint8List aad) {
  final otk = poly1305KeyGen(key, nonce);
  final macData = _macInput(aad, ciphertext);
  final tag = poly1305Mac(otk, macData);

  // Constant-time-ish comparison.
  if (tag.length != expectedTag.length) return null;
  var diff = 0;
  for (var i = 0; i < tag.length; i++) {
    diff |= tag[i] ^ expectedTag[i];
  }
  if (diff != 0) return null;

  return chacha20Xor(key, 1, nonce, ciphertext);
}

/// Build the Poly1305 input per RFC 8439 §2.8.1:
///   AAD || pad16(AAD) || ciphertext || pad16(ciphertext) ||
///   le64(len(AAD)) || le64(len(ciphertext))
Uint8List _macInput(Uint8List aad, Uint8List ciphertext) {
  int padLen(int n) => (16 - (n % 16)) % 16;

  final aadPad = padLen(aad.length);
  final ctPad = padLen(ciphertext.length);
  final out = BytesBuilder(copy: false)
    ..add(aad)
    ..add(Uint8List(aadPad))
    ..add(ciphertext)
    ..add(Uint8List(ctPad))
    ..add(_le64(aad.length))
    ..add(_le64(ciphertext.length));
  return out.toBytes();
}

Uint8List _le64(int n) {
  final b = Uint8List(8);
  final bd = ByteData.sublistView(b);
  // Dart ints on the VM are 64-bit; setUint64 is safe for non-negative len.
  bd.setUint64(0, n, Endian.little);
  return b;
}
