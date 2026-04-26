// Pure-Dart X.509 DER encoding helpers shared by macOS and Linux ECDSA backends.
import 'dart:typed_data';

import 'csprng.dart';

/// Minimal DER encoding for self-signed X.509 certificates.
abstract final class X509Der {
  X509Der._();

  /// Build a TBSCertificate with EC P-256 public key.
  static Uint8List buildTbsCertificate(Uint8List pubKeyBytes) {
    final version = _derTagged(0xa0, _derInteger(Uint8List.fromList([0x02])));
    final serial = _derInteger(Csprng.randomBytes(16));
    final sigAlg = _derSequence([_derOid(const [1, 2, 840, 10045, 4, 3, 2])]);
    final name = _rdnSequence('webdartc');
    final now = DateTime.now().toUtc();
    final notBefore = _utcTime(now);
    final notAfter = _utcTime(now.add(const Duration(days: 730)));
    final validity = _derSequence([notBefore, notAfter]);
    final spki = _derSequence([
      _derSequence([
        _derOid(const [1, 2, 840, 10045, 2, 1]),
        _derOid(const [1, 2, 840, 10045, 3, 1, 7]),
      ]),
      _derBitString(pubKeyBytes),
    ]);
    return _derSequence([version, serial, sigAlg, name, validity, name, spki]);
  }

  /// Wrap TBS + signature into a full Certificate.
  static Uint8List buildCertificate(Uint8List tbs, Uint8List signature) {
    final sigAlg = _derSequence([_derOid(const [1, 2, 840, 10045, 4, 3, 2])]);
    return _derSequence([tbs, sigAlg, _derBitString(signature)]);
  }

  // ── DER primitives ──────────────────────────────────────────────────────

  static Uint8List _derTlv(int tag, Uint8List value) {
    final lenBytes = _derLength(value.length);
    final out = Uint8List(1 + lenBytes.length + value.length);
    out[0] = tag;
    out.setRange(1, 1 + lenBytes.length, lenBytes);
    out.setRange(1 + lenBytes.length, out.length, value);
    return out;
  }

  static Uint8List _derLength(int len) {
    if (len < 128) return Uint8List.fromList([len]);
    if (len < 256) return Uint8List.fromList([0x81, len]);
    return Uint8List.fromList([0x82, len >> 8, len & 0xff]);
  }

  static Uint8List _derSequence(List<Uint8List> items) => _derTlv(0x30, _concat(items));
  static Uint8List _derTagged(int tag, Uint8List content) => _derTlv(tag, content);

  static Uint8List _derInteger(Uint8List value) {
    final out = (value.isNotEmpty && value[0] & 0x80 != 0)
        ? Uint8List.fromList([0x00, ...value])
        : value;
    return _derTlv(0x02, out);
  }

  static Uint8List _derBitString(Uint8List value) {
    final body = Uint8List(value.length + 1);
    body[0] = 0x00;
    body.setRange(1, body.length, value);
    return _derTlv(0x03, body);
  }

  static Uint8List _derOid(List<int> components) {
    final bytes = <int>[];
    bytes.add(40 * components[0] + components[1]);
    for (var i = 2; i < components.length; i++) {
      var v = components[i];
      final sub = <int>[];
      sub.add(v & 0x7f);
      v >>= 7;
      while (v > 0) {
        sub.add(0x80 | (v & 0x7f));
        v >>= 7;
      }
      bytes.addAll(sub.reversed);
    }
    return _derTlv(0x06, Uint8List.fromList(bytes));
  }

  static Uint8List _derUtf8String(String s) => _derTlv(0x0c, Uint8List.fromList(s.codeUnits));

  static Uint8List _rdnSequence(String cn) {
    final oidCn = _derOid(const [2, 5, 4, 3]);
    final val = _derUtf8String(cn);
    final atv = _derSequence([oidCn, val]);
    final rdn = _derTlv(0x31, atv);
    return _derSequence([rdn]);
  }

  static Uint8List _utcTime(DateTime dt) {
    final s = '${_twoDigit(dt.year % 100)}${_twoDigit(dt.month)}${_twoDigit(dt.day)}'
        '${_twoDigit(dt.hour)}${_twoDigit(dt.minute)}${_twoDigit(dt.second)}Z';
    return _derTlv(0x17, Uint8List.fromList(s.codeUnits));
  }

  static String _twoDigit(int n) => n.toString().padLeft(2, '0');

  static Uint8List _concat(List<Uint8List> parts) {
    final total = parts.fold(0, (s, p) => s + p.length);
    final out = Uint8List(total);
    var offset = 0;
    for (final p in parts) {
      out.setRange(offset, offset + p.length, p);
      offset += p.length;
    }
    return out;
  }
}

/// OID 1.2.840.10045.2.1 (id-ecPublicKey) DER-encoded value bytes.
final Uint8List _oidEcPublicKey = Uint8List.fromList(
    const [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);

/// OID 1.2.840.10045.3.1.7 (prime256v1 / P-256) DER-encoded value bytes.
final Uint8List _oidPrime256v1 = Uint8List.fromList(
    const [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);

/// Extract the 65-byte uncompressed P-256 SubjectPublicKey from a self-signed
/// X.509 DER certificate. Returns null when the cert is not a P-256
/// `ecPublicKey` SPKI or when the structure cannot be parsed.
Uint8List? extractEcdsaP256PublicKey(Uint8List certDer) {
  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  final cert = _readTlv(certDer, 0);
  if (cert == null || cert.tag != 0x30) return null;
  if (cert.contentEnd > certDer.length) return null;

  // tbsCertificate ::= SEQUENCE { ... }
  final tbs = _readTlv(certDer, cert.contentStart);
  if (tbs == null || tbs.tag != 0x30) return null;

  // Walk fields of tbsCertificate to locate SubjectPublicKeyInfo.
  // Layout: [0] EXPLICIT version (0xA0), serialNumber (INTEGER 0x02),
  // signature (SEQ 0x30), issuer (SEQ 0x30), validity (SEQ 0x30),
  // subject (SEQ 0x30), subjectPublicKeyInfo (SEQ 0x30).
  final fieldOrder = <int>[];
  var off = tbs.contentStart;
  while (off < tbs.contentEnd) {
    final tlv = _readTlv(certDer, off);
    if (tlv == null) return null;
    fieldOrder.add(off);
    off = tlv.contentEnd;
  }

  // SPKI sits at index after [version?, serial, signature, issuer, validity, subject].
  // Version is OPTIONAL but always emitted by buildTbsCertificate, so use 6.
  // Fall back: locate the SPKI by looking for the *second* SEQUENCE after
  // validity that contains an OID we recognize.
  Uint8List? extractFromSpki(int spkiOffset) {
    final spki = _readTlv(certDer, spkiOffset);
    if (spki == null || spki.tag != 0x30) return null;
    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING }
    final algId = _readTlv(certDer, spki.contentStart);
    if (algId == null || algId.tag != 0x30) return null;
    final algOid = _readTlv(certDer, algId.contentStart);
    if (algOid == null || algOid.tag != 0x06) return null;
    if (!_bytesEq(certDer, algOid.contentStart, algOid.contentEnd,
        _oidEcPublicKey)) {
      return null;
    }
    final params = _readTlv(certDer, algOid.contentEnd);
    if (params == null || params.tag != 0x06) return null;
    if (!_bytesEq(certDer, params.contentStart, params.contentEnd,
        _oidPrime256v1)) {
      return null;
    }
    final bitString = _readTlv(certDer, algId.contentEnd);
    if (bitString == null || bitString.tag != 0x03) return null;
    // BIT STRING content: leading "unused bits" byte then the EC point.
    if (bitString.contentEnd - bitString.contentStart < 2) return null;
    if (certDer[bitString.contentStart] != 0x00) return null;
    final pkLen = bitString.contentEnd - bitString.contentStart - 1;
    if (pkLen != 65) return null;
    if (certDer[bitString.contentStart + 1] != 0x04) return null;
    return Uint8List.sublistView(
      certDer,
      bitString.contentStart + 1,
      bitString.contentEnd,
    );
  }

  if (fieldOrder.length >= 7) {
    final res = extractFromSpki(fieldOrder[6]);
    if (res != null) return res;
  }
  if (fieldOrder.length >= 6) {
    return extractFromSpki(fieldOrder[5]);
  }
  return null;
}

class _Tlv {
  final int tag;
  final int contentStart;
  final int contentEnd;
  _Tlv(this.tag, this.contentStart, this.contentEnd);
}

_Tlv? _readTlv(Uint8List buf, int offset) {
  if (offset >= buf.length) return null;
  final tag = buf[offset];
  if (offset + 1 >= buf.length) return null;
  final lenByte = buf[offset + 1];
  int contentLen;
  int contentStart;
  if (lenByte < 0x80) {
    contentLen = lenByte;
    contentStart = offset + 2;
  } else {
    final n = lenByte & 0x7F;
    if (n == 0 || n > 4) return null;
    if (offset + 2 + n > buf.length) return null;
    contentLen = 0;
    for (var i = 0; i < n; i++) {
      contentLen = (contentLen << 8) | buf[offset + 2 + i];
    }
    contentStart = offset + 2 + n;
  }
  final contentEnd = contentStart + contentLen;
  if (contentEnd > buf.length) return null;
  return _Tlv(tag, contentStart, contentEnd);
}

bool _bytesEq(Uint8List buf, int start, int end, Uint8List expected) {
  if (end - start != expected.length) return false;
  for (var i = 0; i < expected.length; i++) {
    if (buf[start + i] != expected[i]) return false;
  }
  return true;
}
