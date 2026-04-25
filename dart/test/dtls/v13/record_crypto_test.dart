import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/dtls/v13/key_schedule.dart';
import 'package:webdartc/dtls/v13/record.dart';
import 'package:webdartc/dtls/v13/record_crypto.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);

  /// Build a deterministic-but-non-trivial set of TrafficKeys to drive the
  /// AEAD. We don't test against RFC 8448 record-level vectors here because
  /// those vectors are TLS 1.3, not DTLS 1.3; key_schedule_test.dart already
  /// covers the cryptographic derivation matches.
  TrafficKeys keysFromSecret(int seed) {
    final secret = Uint8List.fromList(
      List<int>.generate(32, (i) => (seed + i) & 0xFF),
    );
    return TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: secret,
      keyLength: 16, // AES-128-GCM
    );
  }

  group('DtlsV13RecordCrypto.encrypt', () {
    test('produces a record whose header has S=1 / L=1 and matching length',
        () {
      final keys = keysFromSecret(1);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22, // handshake
        content: bytes(List<int>.generate(40, (i) => i)),
        epoch: 2,
        seqNum: 0x0001,
        keys: keys,
      );
      // Header must start with the unified-header 001SLEE pattern.
      // Top 3 bits = 001, C=0, S=1, L=1, EE = 10 → 0x2E.
      expect(ct[0], equals(0x2E));
      // Length field = inner.length + 1 + 16 (content + content_type + tag).
      final declared = (ct[3] << 8) | ct[4];
      expect(declared, equals(40 + 1 + 16));
      expect(ct.length, equals(5 + declared));
    });

    test('encrypt → decrypt round trip recovers plaintext + content type', () {
      final keys = keysFromSecret(7);
      const type = 23; // application_data
      final plain = bytes(List<int>.generate(120, (i) => 0xA0 ^ i));
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: type,
        content: plain,
        epoch: 3,
        seqNum: 0x0042,
        keys: keys,
      );
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 3,
      );
      expect(out, isNotNull);
      expect(out!.contentType, equals(type));
      expect(out.content, equals(plain));
      expect(out.seqNum, equals(0x0042));
    });

    test('records with successive seq numbers differ in ciphertext', () {
      final keys = keysFromSecret(2);
      final c1 = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.filled(32, 0xCC)),
        epoch: 2,
        seqNum: 0,
        keys: keys,
      );
      final c2 = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.filled(32, 0xCC)),
        epoch: 2,
        seqNum: 1,
        keys: keys,
      );
      // Different nonces ⇒ different ciphertext bodies.
      expect(c1.sublist(5), isNot(equals(c2.sublist(5))));
    });

    test('rejects content that would overflow the 16-bit length field', () {
      final keys = keysFromSecret(3);
      // 0xFFFF - 17 = 65518 is the maximum encryptable content length.
      expect(
        () => DtlsV13RecordCrypto.encrypt(
          contentType: 22,
          content: Uint8List(65520),
          epoch: 2,
          seqNum: 0,
          keys: keys,
        ),
        throwsArgumentError,
      );
    });
  });

  group('DtlsV13RecordCrypto.decrypt', () {
    test('returns null when the AEAD tag is wrong', () {
      final keys = keysFromSecret(11);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.generate(20, (i) => i)),
        epoch: 2,
        seqNum: 5,
        keys: keys,
      );
      // Flip a bit in the tag (last byte).
      ct[ct.length - 1] ^= 0x01;
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 2,
      );
      expect(out, isNull);
    });

    test('returns null when the ciphertext is tampered', () {
      final keys = keysFromSecret(12);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.generate(32, (i) => i)),
        epoch: 2,
        seqNum: 9,
        keys: keys,
      );
      ct[10] ^= 0x40; // somewhere mid-ciphertext
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 2,
      );
      expect(out, isNull);
    });

    test('returns null when the masked sequence number is tampered', () {
      final keys = keysFromSecret(13);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.generate(24, (i) => i)),
        epoch: 2,
        seqNum: 7,
        keys: keys,
      );
      ct[1] ^= 0xFF; // flip the masked seq high byte
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 2,
      );
      // The unmask gives a wrong seq → wrong nonce → AEAD fails.
      expect(out, isNull);
    });

    test('returns null when caller passes the wrong epoch', () {
      final keys = keysFromSecret(14);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10]),
        epoch: 2,
        seqNum: 0,
        keys: keys,
      );
      // The header's low-2-bit epoch was encoded with epoch=2 (=> 10).
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 3, // mismatched low bits (11 vs 10)
      );
      expect(out, isNull);
    });

    test('returns null on truncated input', () {
      final keys = keysFromSecret(15);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10]),
        epoch: 2,
        seqNum: 0,
        keys: keys,
      );
      // Drop the tag.
      final truncated = ct.sublist(0, ct.length - 16);
      final out = DtlsV13RecordCrypto.decrypt(
        record: truncated,
        keys: keys,
        epoch: 2,
      );
      expect(out, isNull);
    });

    test('returns null when the record is not DTLS 1.3 unified', () {
      final keys = keysFromSecret(16);
      // 0x16 is DTLS 1.2 ContentType.handshake — top bits 000.
      final fake = bytes([0x16, 0xFE, 0xFD, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5]);
      final out = DtlsV13RecordCrypto.decrypt(
        record: fake,
        keys: keys,
        epoch: 2,
      );
      expect(out, isNull);
    });

    test('rejects an all-zero inner plaintext (no content type byte)', () {
      // Build a record whose inner plaintext is genuinely all zeros:
      // encrypt with contentType=0 and empty content, then verify decrypt
      // refuses it (RFC 8446 §5.2).
      final keys = keysFromSecret(17);
      // Use the AEAD primitives directly to construct the malformed inner.
      // We encrypt zero bytes with contentType=0 — the inner plaintext is
      // a single zero byte. After stripping trailing zeros that leaves
      // typeIdx = -1 → null.
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 0,
        content: Uint8List(0),
        epoch: 2,
        seqNum: 0,
        keys: keys,
      );
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 2,
      );
      expect(out, isNull);
    });
  });

  group('DtlsV13RecordCrypto sn-mask interaction', () {
    test('masked seq matches unmasking via record.maskSequenceNumber', () {
      final keys = keysFromSecret(99);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.generate(32, (i) => 0xA0 + i)),
        epoch: 2,
        seqNum: 0xC0DE,
        keys: keys,
      );
      // The truncated seq on the wire is masked; manually unmask and check.
      final hdr = DtlsV13Record.parse(ct);
      expect(hdr, isNotNull);
      final copy = Uint8List.fromList(ct);
      DtlsV13Record.maskSequenceNumber(
        record: copy,
        seqOffset: hdr!.seqOffset,
        seqLen: hdr.seqLen,
        ciphertextOffset: hdr.ciphertextOffset,
        snKey: keys.snKey,
      );
      final recovered = (copy[hdr.seqOffset] << 8) | copy[hdr.seqOffset + 1];
      expect(recovered, equals(0xC0DE));
    });
  });
}
