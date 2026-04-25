import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';
// Direct import of the pure-Dart core so we can validate the RFC 8439
// algorithm even on Linux (where the public API is wired to OpenSSL).
// The pure-Dart implementation lives under lib/crypto/ but is not part of
// the public surface area; we reach into it here to exercise the RFC
// reference algorithm and the macOS code path.
import 'package:webdartc/crypto/chacha20_poly1305_pure.dart' as pure;

Uint8List _hex(String s) {
  final h = s.replaceAll(RegExp(r'[\s:]'), '');
  return Uint8List.fromList(List.generate(
      h.length ~/ 2, (i) => int.parse(h.substring(i * 2, i * 2 + 2), radix: 16)));
}

void main() {
  group('ChaCha20Poly1305 (public API, platform backend)', () {
    // RFC 8439 §2.8.2 — AEAD test vector.
    test('RFC 8439 §2.8.2 AEAD test vector', () {
      final key = _hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f'
          '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
      final nonce = _hex('07 00 00 00 40 41 42 43 44 45 46 47');
      final aad = _hex('50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7');
      final plaintext = Uint8List.fromList(
          'Ladies and Gentlemen of the class of \'99: '
                  'If I could offer you only one tip for the future, '
                  'sunscreen would be it.'
              .codeUnits);
      final expectedCiphertext = _hex(
          'd3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2'
          'a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6'
          '3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b'
          '1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36'
          '92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58'
          'fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc'
          '3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b'
          '61 16');
      final expectedTag = _hex('1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91');

      final result = ChaCha20Poly1305.encrypt(key, nonce, plaintext, aad: aad);
      expect(result.ciphertext, equals(expectedCiphertext));
      expect(result.tag, equals(expectedTag));

      final decrypted = ChaCha20Poly1305.decrypt(
          key, nonce, result.ciphertext, result.tag,
          aad: aad);
      expect(decrypted, isNotNull);
      expect(decrypted, equals(plaintext));
    });

    test('encrypt/decrypt roundtrip with AAD', () {
      final key = _hex(
          '0001020304050607 08090a0b0c0d0e0f 1011121314151617 18191a1b1c1d1e1f');
      final nonce = _hex('000102030405060708090a0b');
      final plain = Uint8List.fromList('Hello, ChaCha20-Poly1305!'.codeUnits);
      final aad = Uint8List.fromList('aad bytes'.codeUnits);

      final r = ChaCha20Poly1305.encrypt(key, nonce, plain, aad: aad);
      final got =
          ChaCha20Poly1305.decrypt(key, nonce, r.ciphertext, r.tag, aad: aad);
      expect(got, equals(plain));
    });

    test('roundtrip with empty plaintext and empty AAD', () {
      final key = Uint8List(32);
      final nonce = Uint8List(12);
      final r = ChaCha20Poly1305.encrypt(key, nonce, Uint8List(0));
      expect(r.ciphertext.length, 0);
      final got = ChaCha20Poly1305.decrypt(key, nonce, r.ciphertext, r.tag);
      expect(got, equals(Uint8List(0)));
    });

    test('tampered ciphertext fails authentication', () {
      final key = _hex(
          '0001020304050607 08090a0b0c0d0e0f 1011121314151617 18191a1b1c1d1e1f');
      final nonce = _hex('000102030405060708090a0b');
      final plain = Uint8List.fromList('secret payload'.codeUnits);

      final r = ChaCha20Poly1305.encrypt(key, nonce, plain);
      final tampered = Uint8List.fromList(r.ciphertext);
      tampered[0] ^= 0x01;
      final got = ChaCha20Poly1305.decrypt(key, nonce, tampered, r.tag);
      expect(got, isNull);
    });

    test('tampered tag fails authentication', () {
      final key = _hex(
          '0001020304050607 08090a0b0c0d0e0f 1011121314151617 18191a1b1c1d1e1f');
      final nonce = _hex('000102030405060708090a0b');
      final plain = Uint8List.fromList('secret payload'.codeUnits);

      final r = ChaCha20Poly1305.encrypt(key, nonce, plain);
      final tag = Uint8List.fromList(r.tag);
      tag[0] ^= 0x80;
      final got = ChaCha20Poly1305.decrypt(key, nonce, r.ciphertext, tag);
      expect(got, isNull);
    });

    test('mismatched AAD fails authentication', () {
      final key = _hex(
          '0001020304050607 08090a0b0c0d0e0f 1011121314151617 18191a1b1c1d1e1f');
      final nonce = _hex('000102030405060708090a0b');
      final plain = Uint8List.fromList('payload'.codeUnits);

      final r = ChaCha20Poly1305.encrypt(key, nonce, plain,
          aad: Uint8List.fromList('aad-A'.codeUnits));
      final got = ChaCha20Poly1305.decrypt(key, nonce, r.ciphertext, r.tag,
          aad: Uint8List.fromList('aad-B'.codeUnits));
      expect(got, isNull);
    });
  });

  group('ChaCha20Poly1305 (pure Dart RFC 8439 reference)', () {
    // RFC 8439 §2.5.2 — Poly1305 single-block test vector.
    test('RFC 8439 §2.5.2 Poly1305 vector', () {
      final key = _hex(
          '85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8'
          '01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b');
      final msg = Uint8List.fromList(
          'Cryptographic Forum Research Group'.codeUnits);
      final expected =
          _hex('a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9');
      expect(pure.poly1305Mac(key, msg), equals(expected));
    });

    // RFC 8439 §2.6.2 — Poly1305 key generation from the AEAD key+nonce.
    test('RFC 8439 §2.6.2 Poly1305 key generation', () {
      final key = _hex(
          '80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f'
          '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
      final nonce = _hex('00 00 00 00 00 01 02 03 04 05 06 07');
      final expected = _hex(
          '8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71'
          'a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46');
      expect(pure.poly1305KeyGen(key, nonce), equals(expected));
    });

    // RFC 8439 §2.3.2 — ChaCha20 block function test vector.
    test('RFC 8439 §2.3.2 ChaCha20 block', () {
      final key = _hex(
          '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f'
          '10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f');
      final nonce = _hex('00:00:00:09:00:00:00:4a:00:00:00:00');
      const counter = 1;
      final expected = _hex(
          '10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4'
          'c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e'
          'd2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2'
          'b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e');
      expect(pure.chacha20Block(key, counter, nonce), equals(expected));
    });

    // RFC 8439 §2.8.2 — same AEAD vector validated against the pure Dart
    // implementation directly.
    test('RFC 8439 §2.8.2 AEAD vector via pure Dart', () {
      final key = _hex('80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f'
          '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f');
      final nonce = _hex('07 00 00 00 40 41 42 43 44 45 46 47');
      final aad = _hex('50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7');
      final plaintext = Uint8List.fromList(
          'Ladies and Gentlemen of the class of \'99: '
                  'If I could offer you only one tip for the future, '
                  'sunscreen would be it.'
              .codeUnits);
      final expectedTag = _hex('1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91');

      final r = pure.aeadEncrypt(key, nonce, plaintext, aad);
      expect(r.tag, equals(expectedTag));
      final back = pure.aeadDecrypt(key, nonce, r.ciphertext, r.tag, aad);
      expect(back, equals(plaintext));
    });
  });
}
