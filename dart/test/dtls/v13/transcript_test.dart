import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/sha256.dart';
import 'package:webdartc/dtls/v13/transcript.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);

  /// Build a DTLS handshake message: type(1)+length(3)+msg_seq(2)+
  /// frag_offset(3)+frag_length(3)+body. Used to drive the transcript.
  Uint8List dtlsMsg({
    required int type,
    required int msgSeq,
    int fragmentOffset = 0,
    int? fragmentLength,
    required Uint8List body,
  }) {
    final length = body.length;
    final fragLen = fragmentLength ?? length;
    final out = Uint8List(12 + body.length);
    out[0] = type;
    out[1] = (length >> 16) & 0xFF;
    out[2] = (length >> 8) & 0xFF;
    out[3] = length & 0xFF;
    out[4] = (msgSeq >> 8) & 0xFF;
    out[5] = msgSeq & 0xFF;
    out[6] = (fragmentOffset >> 16) & 0xFF;
    out[7] = (fragmentOffset >> 8) & 0xFF;
    out[8] = fragmentOffset & 0xFF;
    out[9] = (fragLen >> 16) & 0xFF;
    out[10] = (fragLen >> 8) & 0xFF;
    out[11] = fragLen & 0xFF;
    out.setRange(12, out.length, body);
    return out;
  }

  /// What the transcript should hash for a single (type, body) pair: just
  /// the TLS 1.3 handshake header `type(1)+length(3)+body`.
  Uint8List tlsForm(int type, Uint8List body) {
    final length = body.length;
    final out = Uint8List(4 + body.length);
    out[0] = type;
    out[1] = (length >> 16) & 0xFF;
    out[2] = (length >> 8) & 0xFF;
    out[3] = length & 0xFF;
    out.setRange(4, out.length, body);
    return out;
  }

  group('DtlsV13Transcript.addDtlsMessage', () {
    test('hash equals SHA-256 over the TLS-form bytes only', () {
      final body = bytes(List<int>.generate(64, (i) => i));
      final t = DtlsV13Transcript();
      t.addDtlsMessage(dtlsMsg(type: 1, msgSeq: 0, body: body));
      expect(t.hash, equals(Sha256.hash(tlsForm(1, body))));
    });

    test('hash is independent of msg_seq, fragment_offset, fragment_length',
        () {
      final body = bytes(List<int>.generate(32, (i) => 0x80 + i));
      final t1 = DtlsV13Transcript()
        ..addDtlsMessage(
          dtlsMsg(type: 2, msgSeq: 0, body: body),
        );
      final t2 = DtlsV13Transcript()
        ..addDtlsMessage(
          dtlsMsg(
            type: 2,
            msgSeq: 0xBEEF,
            fragmentOffset: 0x123456,
            fragmentLength: 0x7FFFFE,
            body: body,
          ),
        );
      // The DTLS-specific fields must not influence the transcript hash.
      expect(t1.hash, equals(t2.hash));
    });

    test('multiple messages accumulate in order', () {
      final m1 = dtlsMsg(type: 1, msgSeq: 0, body: bytes([0x10, 0x11, 0x12]));
      final m2 = dtlsMsg(type: 2, msgSeq: 1, body: bytes([0x20, 0x21]));
      final t = DtlsV13Transcript()
        ..addDtlsMessage(m1)
        ..addDtlsMessage(m2);

      final concat = Uint8List(
        tlsForm(1, bytes([0x10, 0x11, 0x12])).length +
            tlsForm(2, bytes([0x20, 0x21])).length,
      );
      var off = 0;
      final f1 = tlsForm(1, bytes([0x10, 0x11, 0x12]));
      concat.setRange(off, off + f1.length, f1);
      off += f1.length;
      final f2 = tlsForm(2, bytes([0x20, 0x21]));
      concat.setRange(off, off + f2.length, f2);
      expect(t.hash, equals(Sha256.hash(concat)));
      expect(t.length, equals(2));
    });

    test('rejects messages shorter than the DTLS handshake header', () {
      final t = DtlsV13Transcript();
      expect(
        () => t.addDtlsMessage(Uint8List(11)),
        throwsArgumentError,
      );
    });
  });

  group('DtlsV13Transcript.addRawTlsMessage', () {
    test('appends bytes verbatim and matches matching addDtlsMessage', () {
      final body = bytes(List<int>.generate(8, (i) => i));
      final tDtls = DtlsV13Transcript()
        ..addDtlsMessage(dtlsMsg(type: 11, msgSeq: 7, body: body));
      final tRaw = DtlsV13Transcript()..addRawTlsMessage(tlsForm(11, body));
      expect(tDtls.hash, equals(tRaw.hash));
    });
  });

  group('DtlsV13Transcript.replaceWithSyntheticHash', () {
    test('produces 0xFE || uint24(32) || prev_hash and discards earlier msgs',
        () {
      final body = bytes(List<int>.generate(48, (i) => i));
      final t = DtlsV13Transcript()
        ..addDtlsMessage(dtlsMsg(type: 1, msgSeq: 0, body: body));
      final prevHash = t.hash;

      t.replaceWithSyntheticHash();

      // Length collapses to 1 (only the synthetic message).
      expect(t.length, equals(1));

      // Synthetic message wire form: type=0xFE, length=32, body=prevHash.
      final synthetic = Uint8List(4 + prevHash.length)
        ..[0] = 0xFE
        ..[1] = 0x00
        ..[2] = 0x00
        ..[3] = 0x20
        ..setRange(4, 4 + prevHash.length, prevHash);

      // Hash now reflects only the synthetic message.
      expect(t.hash, equals(Sha256.hash(synthetic)));
    });

    test('appending after replacement chains correctly (HRR scenario)', () {
      // Simulate: ClientHello1 → server HRR → replace with synthetic →
      // append HelloRetryRequest then ClientHello2.
      final ch1Body = bytes(List<int>.generate(40, (i) => 0xA0 + i));
      final hrrBody = bytes(List<int>.generate(20, (i) => 0xB0 + i));
      final ch2Body = bytes(List<int>.generate(40, (i) => 0xC0 + i));

      final t = DtlsV13Transcript()
        ..addDtlsMessage(dtlsMsg(type: 1, msgSeq: 0, body: ch1Body));
      final ch1Hash = t.hash;
      t.replaceWithSyntheticHash();
      // Note: ServerHello with HRR magic (type=2) and ClientHello2 (type=1).
      t
        ..addDtlsMessage(dtlsMsg(type: 2, msgSeq: 0, body: hrrBody))
        ..addDtlsMessage(dtlsMsg(type: 1, msgSeq: 1, body: ch2Body));

      // Re-derive the expected hash manually.
      final synthetic = Uint8List(4 + ch1Hash.length)
        ..[0] = 0xFE
        ..[1] = 0x00
        ..[2] = 0x00
        ..[3] = 0x20
        ..setRange(4, 4 + ch1Hash.length, ch1Hash);
      final hrrTls = tlsForm(2, hrrBody);
      final ch2Tls = tlsForm(1, ch2Body);
      final concat = Uint8List(synthetic.length + hrrTls.length + ch2Tls.length);
      var off = 0;
      concat.setRange(off, off + synthetic.length, synthetic);
      off += synthetic.length;
      concat.setRange(off, off + hrrTls.length, hrrTls);
      off += hrrTls.length;
      concat.setRange(off, off + ch2Tls.length, ch2Tls);
      expect(t.hash, equals(Sha256.hash(concat)));
    });
  });

  group('DtlsV13Transcript.clear', () {
    test('removes all accumulated messages', () {
      final t = DtlsV13Transcript()
        ..addDtlsMessage(dtlsMsg(type: 1, msgSeq: 0, body: bytes([1, 2, 3])));
      expect(t.length, equals(1));
      t.clear();
      expect(t.length, equals(0));
      // Hash of empty transcript = SHA-256("") (used by Derive-Secret).
      expect(t.hash, equals(Sha256.hash(Uint8List(0))));
    });
  });
}
