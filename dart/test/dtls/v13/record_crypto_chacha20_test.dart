import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/dtls/v13/cipher_suite.dart';
import 'package:webdartc/dtls/v13/key_schedule.dart';
import 'package:webdartc/dtls/v13/record_crypto.dart';

/// Record-layer tests for `TLS_CHACHA20_POLY1305_SHA256` (0x1303). Mirrors
/// the AES-GCM coverage in `record_crypto_test.dart` so a regression in
/// either AEAD primitive shows up in the suite.
void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);

  TrafficKeys keysFromSecret(int seed) {
    final secret = Uint8List.fromList(
      List<int>.generate(32, (i) => (seed + i) & 0xFF),
    );
    return TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: secret,
      keyLength: 32, // ChaCha20 256-bit key
    );
  }

  const chacha = TlsV13CipherSuite.chacha20Poly1305Sha256;

  group('DtlsV13RecordCrypto with ChaCha20-Poly1305 (0x1303)', () {
    test('encrypt → decrypt round trip recovers plaintext + content type', () {
      final keys = keysFromSecret(13);
      const type = 23;
      final plain = bytes(List<int>.generate(200, (i) => 0xA5 ^ i));
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: type,
        content: plain,
        epoch: 3,
        seqNum: 0x0042,
        keys: keys,
        cipherSuite: chacha,
      );
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 3,
        cipherSuite: chacha,
      );
      expect(out, isNotNull);
      expect(out!.contentType, equals(type));
      expect(out.content, equals(plain));
      expect(out.seqNum, equals(0x0042));
    });

    test('records under different seq nums produce different ciphertext', () {
      final keys = keysFromSecret(17);
      final c1 = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.filled(32, 0x55)),
        epoch: 2,
        seqNum: 0,
        keys: keys,
        cipherSuite: chacha,
      );
      final c2 = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.filled(32, 0x55)),
        epoch: 2,
        seqNum: 1,
        keys: keys,
        cipherSuite: chacha,
      );
      expect(c1.sublist(5), isNot(equals(c2.sublist(5))));
    });

    test('decrypt returns null on tampered AEAD tag', () {
      final keys = keysFromSecret(19);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.generate(20, (i) => i)),
        epoch: 2,
        seqNum: 5,
        keys: keys,
        cipherSuite: chacha,
      );
      ct[ct.length - 1] ^= 0x01;
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 2,
        cipherSuite: chacha,
      );
      expect(out, isNull);
    });

    test('decrypt returns null on tampered ciphertext body', () {
      final keys = keysFromSecret(23);
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.generate(20, (i) => i)),
        epoch: 2,
        seqNum: 5,
        keys: keys,
        cipherSuite: chacha,
      );
      // Flip a bit in the middle of the body (after the 5-byte header).
      ct[10] ^= 0x40;
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: keys,
        epoch: 2,
        cipherSuite: chacha,
      );
      expect(out, isNull);
    });

    test('decrypting a ChaCha20 record under the default AES path fails', () {
      // Same 32-byte traffic secret derives 32-byte ChaCha20 keys *and*
      // 16-byte AES keys; build both and confirm the AES decrypt path
      // can't read a record produced by the ChaCha20 path.
      final secret = Uint8List.fromList(
        List<int>.generate(32, (i) => (i * 5) & 0xFF),
      );
      final chachaKeys = TlsV13KeySchedule.deriveTrafficKeys(
        trafficSecret: secret,
        keyLength: 32,
      );
      final aesKeys = TlsV13KeySchedule.deriveTrafficKeys(
        trafficSecret: secret,
        keyLength: 16,
      );
      final ct = DtlsV13RecordCrypto.encrypt(
        contentType: 22,
        content: bytes(List<int>.generate(20, (i) => i)),
        epoch: 2,
        seqNum: 1,
        keys: chachaKeys,
        cipherSuite: chacha,
      );
      final out = DtlsV13RecordCrypto.decrypt(
        record: ct,
        keys: aesKeys, // AES-keyed, default suite
        epoch: 2,
      );
      expect(out, isNull);
    });
  });
}
