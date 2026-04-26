import 'dart:typed_data';

import '../crypto/sha256.dart';
import 'cipher_suite.dart';
import 'record.dart';

/// DTLS 1.2 handshake state (RFC 6347 §4.2).
enum DtlsHandshakeState {
  initial,
  // Client side
  sentClientHello,
  sentClientHelloWithCookie,
  sentCertificate,
  sentClientKeyExchange,
  sentFinished,
  // Server side
  sentServerHello,
  sentCertificate_,
  sentServerKeyExchange_,
  sentServerHelloDone,
  sentChangeCipherSpec,
  sentServerFinished,
  // Shared
  connected,
  failed,
}

/// Accumulated handshake transcript for Finished verification.
final class HandshakeTranscript {
  final _msgs = <Uint8List>[];

  void add(Uint8List hsMsg) => _msgs.add(Uint8List.fromList(hsMsg));
  void clear() => _msgs.clear();
  void removeLast() {
    if (_msgs.isNotEmpty) _msgs.removeLast();
  }

  /// SHA-256 hash of all handshake message bytes (12-byte header + body).
  Uint8List get hash => Sha256.hash(bytes);

  /// Concatenated handshake bytes accumulated so far.
  Uint8List get bytes {
    var total = 0;
    for (final m in _msgs) { total += m.length; }
    final combined = Uint8List(total);
    var offset = 0;
    for (final m in _msgs) {
      combined.setRange(offset, offset + m.length, m);
      offset += m.length;
    }
    return combined;
  }
}

/// Builds DTLS 1.2 handshake messages.
abstract final class DtlsHandshakeBuilder {
  DtlsHandshakeBuilder._();

  static int _msgSeq = 0;

  /// Build a ClientHello (RFC 6347 §4.2.1).
  static Uint8List buildClientHello({
    required Uint8List random, // 32 bytes
    required Uint8List sessionId, // 0 or 32 bytes
    Uint8List? cookie, // null or 1–255 bytes
    required List<CipherSuite> suites,
  }) {
    _msgSeq = 0;
    final body = _buildClientHelloBody(random, sessionId, cookie, suites);
    return _wrap(DtlsHandshakeType.clientHello, body, msgSeq: _msgSeq++);
  }

  static Uint8List _buildClientHelloBody(
    Uint8List random,
    Uint8List sessionId,
    Uint8List? cookie,
    List<CipherSuite> suites,
  ) {
    final buf = <int>[];
    // Version: DTLS 1.2 = 0xFEFD
    buf.addAll([0xFE, 0xFD]);
    // Random: 32 bytes
    buf.addAll(random);
    // Session ID
    buf.add(sessionId.length);
    buf.addAll(sessionId);
    // Cookie
    if (cookie != null && cookie.isNotEmpty) {
      buf.add(cookie.length);
      buf.addAll(cookie);
    } else {
      buf.add(0); // empty cookie
    }
    // Cipher suites
    buf.add(0);
    buf.add(suites.length * 2);
    for (final s in suites) {
      buf.add(s.major);
      buf.add(s.minor);
    }
    // Compression: null only
    buf.add(1);
    buf.add(0);
    // Extensions
    final extBuf = <int>[];
    // extended_master_secret (0x0017), empty data — required by Chrome
    extBuf.addAll([0x00, 0x17, 0x00, 0x00]);
    // supported_groups (0x000A) — secp256r1 (0x0017)
    extBuf.addAll([0x00, 0x0A, 0x00, 0x04]); // type + length
    extBuf.addAll([0x00, 0x02, 0x00, 0x17]); // list_len=2, secp256r1
    // signature_algorithms (0x000D) — ecdsa_secp256r1_sha256 (0x0403)
    extBuf.addAll([0x00, 0x0D, 0x00, 0x04]); // type + length
    extBuf.addAll([0x00, 0x02, 0x04, 0x03]); // list_len=2, ecdsa_sha256
    // use_srtp (0x000E) — SRTP_AES128_CM_HMAC_SHA1_80 (0x0001)
    extBuf.addAll([0x00, 0x0E, 0x00, 0x05]);
    extBuf.addAll([0x00, 0x02]); // 2 bytes of profiles
    extBuf.addAll([0x00, 0x01]); // SRTP_AES128_CM_HMAC_SHA1_80
    extBuf.add(0x00); // no MKI
    // Extensions length
    buf.add((extBuf.length >> 8) & 0xFF);
    buf.add(extBuf.length & 0xFF);
    buf.addAll(extBuf);
    return Uint8List.fromList(buf);
  }

  /// Build ClientKeyExchange with ECDH public key (RFC 4492 §5.7).
  static Uint8List buildClientKeyExchange({
    required Uint8List publicKeyBytes, // 65 bytes uncompressed P-256
    required int msgSeq,
  }) {
    // ECPoint: length-prefixed
    final body = Uint8List(1 + publicKeyBytes.length);
    body[0] = publicKeyBytes.length;
    body.setRange(1, body.length, publicKeyBytes);
    return _wrap(DtlsHandshakeType.clientKeyExchange, body, msgSeq: msgSeq);
  }

  /// Build Certificate message.
  static Uint8List buildCertificate({
    required Uint8List certDer,
    required int msgSeq,
  }) {
    // certificate_list: 3-byte length of list, then per-cert 3-byte length + DER
    final certBytes = Uint8List(3 + certDer.length);
    certBytes[0] = (certDer.length >> 16) & 0xFF;
    certBytes[1] = (certDer.length >> 8) & 0xFF;
    certBytes[2] = certDer.length & 0xFF;
    certBytes.setRange(3, certBytes.length, certDer);

    final body = Uint8List(3 + certBytes.length);
    body[0] = (certBytes.length >> 16) & 0xFF;
    body[1] = (certBytes.length >> 8) & 0xFF;
    body[2] = certBytes.length & 0xFF;
    body.setRange(3, body.length, certBytes);
    return _wrap(DtlsHandshakeType.certificate, body, msgSeq: msgSeq);
  }

  /// Build CertificateVerify.
  static Uint8List buildCertificateVerify({
    required Uint8List signature,
    required int msgSeq,
  }) {
    // SignatureAndHashAlgorithm: SHA-256(4) + ECDSA(3)
    final body = Uint8List(4 + signature.length);
    body[0] = 0x04; // SHA-256
    body[1] = 0x03; // ECDSA
    body[2] = (signature.length >> 8) & 0xFF;
    body[3] = signature.length & 0xFF;
    body.setRange(4, body.length, signature);
    return _wrap(DtlsHandshakeType.certificateVerify, body, msgSeq: msgSeq);
  }

  /// Build ServerHello (RFC 5246 §7.4.1.3).
  static Uint8List buildServerHello({
    required Uint8List random, // 32 bytes
    required Uint8List sessionId, // 0 or 32 bytes
    required CipherSuite suite,
    required int msgSeq,
    bool extendedMasterSecret = true,
    List<int>? srtpProfile, // 2-byte SRTP profile ID if use_srtp needed
  }) {
    final buf = <int>[];
    // Version: DTLS 1.2 = 0xFEFD
    buf.addAll([0xFE, 0xFD]);
    // Random: 32 bytes
    buf.addAll(random);
    // Session ID
    buf.add(sessionId.length);
    buf.addAll(sessionId);
    // Cipher suite
    buf.add(suite.major);
    buf.add(suite.minor);
    // Compression: null
    buf.add(0);

    // Extensions
    final extBuf = <int>[];
    if (extendedMasterSecret) {
      // extended_master_secret (0x0017), empty data
      extBuf.addAll([0x00, 0x17, 0x00, 0x00]);
    }
    if (srtpProfile != null) {
      // use_srtp (0x000E)
      // data: profiles_length(2) + profile(2) + mki_length(1)
      extBuf.addAll([0x00, 0x0E, 0x00, 0x05]);
      extBuf.addAll([0x00, 0x02]); // 2 bytes of profiles
      extBuf.addAll(srtpProfile);
      extBuf.add(0x00); // no MKI
    }
    if (extBuf.isNotEmpty) {
      buf.add((extBuf.length >> 8) & 0xFF);
      buf.add(extBuf.length & 0xFF);
      buf.addAll(extBuf);
    }

    return _wrap(
      DtlsHandshakeType.serverHello,
      Uint8List.fromList(buf),
      msgSeq: msgSeq,
    );
  }

  /// Build ServerKeyExchange for ECDHE (RFC 4492 §5.4).
  static Uint8List buildServerKeyExchange({
    required Uint8List ecPublicKey, // 65 bytes uncompressed P-256
    required Uint8List signature, // ECDSA signature of params
    required int msgSeq,
  }) {
    final buf = <int>[];
    // ECParameters: named_curve(3), secp256r1(0x0017)
    buf.addAll([0x03, 0x00, 0x17]);
    // ECPoint
    buf.add(ecPublicKey.length);
    buf.addAll(ecPublicKey);
    // Signature: SHA-256(4) + ECDSA(3)
    buf.addAll([0x04, 0x03]);
    buf.add((signature.length >> 8) & 0xFF);
    buf.add(signature.length & 0xFF);
    buf.addAll(signature);
    return _wrap(
      DtlsHandshakeType.serverKeyExchange,
      Uint8List.fromList(buf),
      msgSeq: msgSeq,
    );
  }

  /// Build ServerHelloDone (RFC 5246 §7.4.5) — empty body.
  static Uint8List buildServerHelloDone({required int msgSeq}) {
    return _wrap(
      DtlsHandshakeType.serverHelloDone,
      Uint8List(0),
      msgSeq: msgSeq,
    );
  }

  /// Build ChangeCipherSpec (not a handshake message, but a separate record).
  static Uint8List buildChangeCipherSpec() {
    return Uint8List.fromList([0x01]);
  }

  /// Build Finished.
  static Uint8List buildFinished({
    required Uint8List verifyData, // 12 bytes
    required int msgSeq,
  }) {
    return _wrap(DtlsHandshakeType.finished, verifyData, msgSeq: msgSeq);
  }

  static Uint8List _wrap(int msgType, Uint8List body, {required int msgSeq}) {
    final hdr = DtlsHandshakeHeader(
      msgType: msgType,
      length: body.length,
      messageSeq: msgSeq,
      fragmentOffset: 0,
      fragmentLength: body.length,
      body: body,
    );
    return hdr.encode();
  }
}
