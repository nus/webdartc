import 'dart:typed_data';

import 'csprng.dart';

/// X25519 Diffie-Hellman on Curve25519 (RFC 7748).
///
/// Pure-Dart implementation using `BigInt` for field arithmetic. Operates
/// in arithmetic time, so timing side channels can leak the scalar — for
/// the typical WebRTC handshake this is acceptable because each session
/// uses a fresh ephemeral key, but a hardened deployment should swap this
/// for a constant-time implementation.
abstract final class X25519 {
  X25519._();

  /// Field prime: 2^255 − 19.
  static final BigInt _p =
      (BigInt.one << 255) - BigInt.from(19);

  /// Curve constant `a24 = (A − 2)/4` for Curve25519, where A = 486662.
  static final BigInt _a24 = BigInt.from(121665);

  /// Standard X25519 base point: u = 9 (RFC 7748 §4.1).
  static final Uint8List _basepoint = () {
    final b = Uint8List(32);
    b[0] = 9;
    return b;
  }();

  /// Compute `scalar * u` per RFC 7748 §5. Both [scalar] and [u] are 32
  /// bytes in little-endian; the return is the 32-byte little-endian
  /// `u`-coordinate of the resulting Montgomery curve point.
  static Uint8List scalarMult(Uint8List scalar, Uint8List u) {
    if (scalar.length != 32) {
      throw ArgumentError('X25519 scalar must be 32 bytes');
    }
    if (u.length != 32) {
      throw ArgumentError('X25519 u-coordinate must be 32 bytes');
    }
    final k = _decodeScalar(scalar);
    final uBig = _decodeU(u);
    return _encodeLE(_ladder(k, uBig));
  }

  /// Compute `scalar * basepoint` — the public key for an X25519 private key.
  static Uint8List scalarMultBase(Uint8List scalar) =>
      scalarMult(scalar, _basepoint);

  /// Decode a 32-byte little-endian scalar with the RFC 7748 §5 clamping
  /// applied: clear the low 3 bits, clear the highest bit, set bit 254.
  static BigInt _decodeScalar(Uint8List scalar) {
    final clamped = Uint8List.fromList(scalar);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    return _decodeLE(clamped);
  }

  /// Decode a 32-byte little-endian u-coordinate, masking the high bit.
  static BigInt _decodeU(Uint8List u) {
    final masked = Uint8List.fromList(u);
    masked[31] &= 127;
    return _decodeLE(masked);
  }

  static BigInt _decodeLE(Uint8List bytes) {
    var n = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      n = (n << 8) | BigInt.from(bytes[i]);
    }
    return n;
  }

  static Uint8List _encodeLE(BigInt n) {
    var v = n % _p;
    final out = Uint8List(32);
    final mask = BigInt.from(0xFF);
    for (var i = 0; i < 32; i++) {
      out[i] = (v & mask).toInt();
      v = v >> 8;
    }
    return out;
  }

  /// Montgomery ladder per RFC 7748 §5. Performs the differential addition
  /// chain to compute `k * (u, ?)` on Curve25519, returning just the
  /// resulting u-coordinate (the y-coordinate is unused).
  static BigInt _ladder(BigInt k, BigInt u) {
    final x1 = u;
    var x2 = BigInt.one;
    var z2 = BigInt.zero;
    var x3 = u;
    var z3 = BigInt.one;
    var swap = 0;

    for (var t = 254; t >= 0; t--) {
      final kt = ((k >> t) & BigInt.one).toInt();
      swap ^= kt;
      if (swap == 1) {
        var tmp = x2; x2 = x3; x3 = tmp;
        tmp = z2; z2 = z3; z3 = tmp;
      }
      swap = kt;

      final a = (x2 + z2) % _p;
      final aa = (a * a) % _p;
      final b = (x2 - z2) % _p;
      final bb = (b * b) % _p;
      final e = (aa - bb) % _p;
      final c = (x3 + z3) % _p;
      final d = (x3 - z3) % _p;
      final da = (d * a) % _p;
      final cb = (c * b) % _p;

      final dacb = (da + cb) % _p;
      x3 = (dacb * dacb) % _p;
      final dasubcb = (da - cb) % _p;
      z3 = (x1 * ((dasubcb * dasubcb) % _p)) % _p;
      x2 = (aa * bb) % _p;
      z2 = (e * ((aa + (_a24 * e) % _p) % _p)) % _p;
    }

    if (swap == 1) {
      var tmp = x2; x2 = x3; x3 = tmp;
      tmp = z2; z2 = z3; z3 = tmp;
    }

    // Return x_2 / z_2 = x_2 * z_2^(p−2) mod p (Fermat's little theorem).
    final z2inv = z2.modPow(_p - BigInt.two, _p);
    return (x2 * z2inv) % _p;
  }
}

/// Ephemeral X25519 key pair suitable for one DTLS handshake.
///
/// API parallels [EcdhKeyPair] (P-256) so callers can swap curves without
/// touching the surrounding code. The 32-byte private scalar is held
/// privately; only the (likewise 32-byte) public u-coordinate is exposed.
final class X25519KeyPair {
  /// Public key — the 32-byte little-endian u-coordinate of `private * 9`.
  /// Suitable for placement in a TLS 1.3 / DTLS 1.3 `key_share` extension
  /// for the `x25519` named group (0x001D).
  final Uint8List publicKeyBytes;

  final Uint8List _privateKey;

  X25519KeyPair._(this._privateKey, this.publicKeyBytes);

  /// Generate a random ephemeral key pair using [Csprng].
  static X25519KeyPair generate() {
    final priv = Csprng.randomBytes(32);
    final pub = X25519.scalarMultBase(priv);
    return X25519KeyPair._(priv, pub);
  }

  /// ECDH shared secret with the peer's 32-byte X25519 public key.
  ///
  /// Returns null when the result is the all-zero point — RFC 8446 §7.4.2
  /// requires aborting the handshake in that case so we surface it
  /// explicitly. Otherwise returns the 32-byte little-endian u-coordinate
  /// of `private * peer_public`.
  Uint8List? computeSharedSecret(Uint8List peerPublicKey) {
    final shared = X25519.scalarMult(_privateKey, peerPublicKey);
    var allZero = true;
    for (final b in shared) {
      if (b != 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) return null;
    return shared;
  }
}
