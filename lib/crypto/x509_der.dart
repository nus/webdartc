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
