import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

Uint8List hex(String s) => Uint8List.fromList(
    List.generate(s.replaceAll(' ', '').length ~/ 2,
        (i) => int.parse(s.replaceAll(' ', '').substring(i * 2, i * 2 + 2), radix: 16)));

void main() {
  group('AesGcm', () {
    // NIST SP 800-38D Test Case 3
    test('NIST SP 800-38D Test Case 3', () {
      final key = hex('feffe9928665731c6d6a8f9467308308');
      final iv = hex('cafebabefacedbaddecaf888');
      final plaintext = hex(
          'd9313225f88406e5a55909c5aff5269a'
          '86a7a9531534f7da2e4c303d8a318a72'
          '1c3c0c95956809532fcf0e2449a6b525'
          'b16aedf5aa0de657ba637b391aafd255');
      final expectedCiphertext = hex(
          '42831ec2217774244b7221b784d0d49c'
          'e3aa212f2c02a4e035c17e2329aca12e'
          '21d514b25466931c7d8f6a5aac84aa05'
          '1ba30b396a0aac973d58e091473f5985');
      final expectedTag = hex('4d5c2af327cd64a62cf35abd2ba6fab4');

      final result = AesGcm.encrypt(key, iv, plaintext);
      expect(result.ciphertext, equals(expectedCiphertext));
      expect(result.tag, equals(expectedTag));

      // Decrypt
      final decrypted = AesGcm.decrypt(
          key, iv, result.ciphertext, Uint8List.fromList(result.tag));
      expect(decrypted, isNotNull);
      expect(decrypted, equals(plaintext));
    });

    test('encrypt/decrypt roundtrip', () {
      final key = hex('00112233445566778899aabbccddeeff');
      final iv = hex('000000000000000000000001');
      final plain = Uint8List.fromList('Hello, AES-GCM!'.codeUnits);
      final aad = Uint8List.fromList('additional data'.codeUnits);

      final result = AesGcm.encrypt(key, iv, plain, aad: aad);
      final decrypted = AesGcm.decrypt(
          key, iv, result.ciphertext, Uint8List.fromList(result.tag),
          aad: aad);
      expect(decrypted, equals(plain));
    });

    test('auth tag verification fails on tampered ciphertext', () {
      final key = hex('00112233445566778899aabbccddeeff');
      final iv = hex('000000000000000000000001');
      final plain = Uint8List.fromList('secret'.codeUnits);

      final result = AesGcm.encrypt(key, iv, plain);
      // Tamper with ciphertext
      final tampered = Uint8List.fromList(result.ciphertext);
      tampered[0] ^= 0xFF;
      final decrypted = AesGcm.decrypt(
          key, iv, tampered, Uint8List.fromList(result.tag));
      expect(decrypted, isNull);
    });
  });
}
