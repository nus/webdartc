import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/hkdf.dart';
import 'package:webdartc/dtls/v13/record.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);

  group('DtlsV13Record header', () {
    test('build sets the unified header bit pattern (C=0, S=1, L=1)', () {
      final ct = bytes(List<int>.generate(20, (i) => i + 1));
      final rec = DtlsV13Record.build(epoch: 2, seqNum: 0x1234, ciphertext: ct);
      // header byte: bits 001 | C=0 | S=1 | L=1 | EE=10 → 0x2C | 0x02 = 0x2E
      expect(rec[0], equals(0x2E));
      // 16-bit truncated seq
      expect(rec[1], equals(0x12));
      expect(rec[2], equals(0x34));
      // length = 20
      expect(rec[3], equals(0x00));
      expect(rec[4], equals(0x14));
      // ciphertext follows
      expect(rec.sublist(5), equals(ct));
    });

    test('header epoch low-bit encoding wraps at 4', () {
      final ct = Uint8List(16);
      for (final epoch in [0, 1, 2, 3, 4, 5, 6, 7]) {
        final rec = DtlsV13Record.build(
          epoch: epoch,
          seqNum: 0,
          ciphertext: ct,
        );
        expect(rec[0] & 0x03, equals(epoch & 0x03), reason: 'epoch=$epoch');
        expect(rec[0] & 0xFC, equals(0x2C));
      }
    });

    test('parse round-trips a record built by build()', () {
      final ct = bytes(List<int>.generate(32, (i) => 0xA0 + i));
      final rec = DtlsV13Record.build(
        epoch: 3,
        seqNum: 0xBEEF,
        ciphertext: ct,
      );
      final hdr = DtlsV13Record.parse(rec);
      expect(hdr, isNotNull);
      expect(hdr!.epochLowBits, equals(3));
      expect(hdr.seqLen, equals(2));
      expect(hdr.seqOffset, equals(1));
      expect(hdr.truncatedSeq, equals(0xBEEF));
      expect(hdr.length, equals(32));
      expect(hdr.ciphertextOffset, equals(5));
      expect(hdr.ciphertextLength, equals(32));
    });

    test('parse rejects records that do not start with `001`', () {
      // Top bits 010 — not DTLS 1.3 unified.
      expect(DtlsV13Record.parse(bytes([0x40, 0, 0, 0])), isNull);
      // Top bits 000 — looks like a DTLSPlaintext (e.g. ContentType=22).
      expect(DtlsV13Record.parse(bytes([0x16, 0, 0, 0])), isNull);
    });

    test('parse rejects truncated input', () {
      expect(DtlsV13Record.parse(Uint8List(0)), isNull);
      // Header byte alone, no seq/length/ciphertext.
      expect(DtlsV13Record.parse(bytes([0x2E])), isNull);
    });

    test('parse refuses Connection ID variants (C=1)', () {
      // Bit 3 set → CID present, unsupported.
      expect(DtlsV13Record.parse(bytes([0x3E, 0, 0, 0, 0])), isNull);
    });
  });

  group('DtlsV13Record.buildNonce', () {
    test('XORs left-padded 64-bit seq with static_iv (no epoch)', () {
      final iv = bytes([
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
      ]);
      final n = DtlsV13Record.buildNonce(iv, 0x0102030405);
      // RFC 9147 §4.2.1: epoch is not packed into the nonce. The 48-bit
      // sequence number is right-aligned in the last 8 bytes, with the
      // top 16 bits zero (since DTLS seq is 48 bits).
      expect(
        n,
        equals(bytes([
          0x00, 0x00, 0x00, 0x00, // padding (4 bytes)
          0x00, 0x00,             // top 16 bits of 64-bit seq (always 0 for 48-bit DTLS seq)
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // 48-bit seq
        ])),
      );
    });

    test('preserves static_iv bits where seq has zeros', () {
      final iv = bytes([
        0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66,
      ]);
      final n = DtlsV13Record.buildNonce(iv, 0x000000000001);
      // First 6 bytes unchanged (padding + zero top of seq).
      expect(n.sublist(0, 6), equals(iv.sublist(0, 6)));
      // Last byte XORed with 0x01.
      expect(n[11], equals(iv[11] ^ 0x01));
    });

    test('rejects non-12-byte static_iv', () {
      expect(
        () => DtlsV13Record.buildNonce(bytes([0]), 0),
        throwsArgumentError,
      );
    });
  });

  group('DtlsV13Record.maskSequenceNumber', () {
    // sn_key derived per RFC 9147 §4.2.3 from a traffic secret.
    Uint8List snKey() {
      final secret = bytes(List<int>.generate(32, (i) => i));
      return Hkdf.expandLabel(
        secret: secret,
        label: 'sn',
        context: Uint8List(0),
        length: 16,
      );
    }

    test('masking is symmetric (apply twice = identity)', () {
      final ct = bytes(List<int>.generate(32, (i) => 0x80 ^ i));
      final original = DtlsV13Record.build(
        epoch: 2,
        seqNum: 0x1234,
        ciphertext: ct,
      );
      final masked = Uint8List.fromList(original);
      final key = snKey();

      DtlsV13Record.maskSequenceNumber(
        record: masked,
        seqOffset: DtlsV13Record.seqOffsetForBuild,
        seqLen: 2,
        ciphertextOffset: DtlsV13Record.ciphertextOffsetForBuild,
        snKey: key,
      );
      // After one mask, seq bytes should differ for typical keys.
      expect(masked.sublist(1, 3), isNot(equals(original.sublist(1, 3))));

      DtlsV13Record.maskSequenceNumber(
        record: masked,
        seqOffset: DtlsV13Record.seqOffsetForBuild,
        seqLen: 2,
        ciphertextOffset: DtlsV13Record.ciphertextOffsetForBuild,
        snKey: key,
      );
      // After unmask, full record matches the original.
      expect(masked, equals(original));
    });

    test('changing the ciphertext sample changes the mask', () {
      final ct1 = bytes(List<int>.generate(32, (_) => 0x00));
      final ct2 = bytes(List<int>.generate(32, (_) => 0xFF));
      final r1 = DtlsV13Record.build(epoch: 2, seqNum: 0xAA55, ciphertext: ct1);
      final r2 = DtlsV13Record.build(epoch: 2, seqNum: 0xAA55, ciphertext: ct2);
      final key = snKey();
      DtlsV13Record.maskSequenceNumber(
        record: r1,
        seqOffset: 1,
        seqLen: 2,
        ciphertextOffset: 5,
        snKey: key,
      );
      DtlsV13Record.maskSequenceNumber(
        record: r2,
        seqOffset: 1,
        seqLen: 2,
        ciphertextOffset: 5,
        snKey: key,
      );
      expect(r1.sublist(1, 3), isNot(equals(r2.sublist(1, 3))));
    });

    test('rejects ciphertext shorter than 16 bytes', () {
      final shortRec = DtlsV13Record.build(
        epoch: 2,
        seqNum: 0,
        ciphertext: bytes(List<int>.generate(8, (i) => i)),
      );
      expect(
        () => DtlsV13Record.maskSequenceNumber(
          record: shortRec,
          seqOffset: 1,
          seqLen: 2,
          ciphertextOffset: 5,
          snKey: Uint8List(16),
        ),
        throwsArgumentError,
      );
    });
  });
}
