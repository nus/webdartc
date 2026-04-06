import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

Uint8List hex(String s) => Uint8List.fromList(
    List.generate(s.replaceAll(' ', '').length ~/ 2,
        (i) => int.parse(s.replaceAll(' ', '').substring(i * 2, i * 2 + 2), radix: 16)));

void main() {
  group('SrtpContext', () {
    final keyMaterial = Uint8List(60);

    test('fromKeyMaterial does not throw', () {
      expect(
        () => SrtpContext.fromKeyMaterial(
          keyMaterial: keyMaterial,
          profile: SrtpProfile.aesCm128HmacSha1_80,
          isClient: true,
        ),
        returnsNormally,
      );
    });

    test('self roundtrip', () {
      final ctx = SrtpContext.fromKeyMaterial(
        keyMaterial: keyMaterial,
        profile: SrtpProfile.aesCm128HmacSha1_80,
        isClient: true,
      );
      final rtp = Uint8List(32);
      rtp[0] = 0x80; rtp[1] = 0x60;
      rtp[2] = 0x00; rtp[3] = 0x01;
      for (var i = 0; i < 20; i++) { rtp[12 + i] = i; }
      final srtp = ctx.encryptRtp(rtp);
      expect(srtp.length, equals(42)); // 32 + 10 auth tag
      final dec = ctx.decryptRtp(srtp);
      expect(dec.isOk, isTrue);
      expect(dec.value, equals(rtp));
    });

    test('server encrypt → client decrypt (cross-context)', () {
      final km = Uint8List.fromList(List.generate(60, (i) => i + 1));
      final server = SrtpContext.fromKeyMaterial(
          keyMaterial: km, profile: SrtpProfile.aesCm128HmacSha1_80, isClient: false);
      final client = SrtpContext.fromKeyMaterial(
          keyMaterial: km, profile: SrtpProfile.aesCm128HmacSha1_80, isClient: true);
      final rtp = Uint8List.fromList([
        0x80, 0x6F, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00,
        0x12, 0x34, 0x56, 0x78, 0x01, 0x02, 0x03, 0x04,
      ]);
      final srtp = server.encryptRtp(rtp);
      final dec = client.decryptRtp(srtp);
      expect(dec.isOk, isTrue);
      expect(dec.value, equals(rtp));
    });
  });

  // Verified against Pion SRTP library and Python pycryptodome
  group('SRTP full packet test vector', () {
    test('KDF produces expected session keys', () {
      final masterKey = hex('cbb4dbee739b8770cd9e2bc656c807ff');
      final masterSalt = hex('be1ce0813afccf2904b688a13b47');

      // Use the KDF directly: AES-CM(masterKey, salt_with_label || 0x0000)
      // label=0 (enc key): no XOR on salt
      final iv0 = Uint8List(16);
      iv0.setRange(0, 14, masterSalt);
      final encKey = AesCm.encrypt(masterKey, iv0, Uint8List(16));
      expect(encKey, equals(hex('e37055f56e5a681ed4277434b7a4e2ce')));

      // label=1 (auth key): salt[7] ^= 1
      final iv1 = Uint8List(16);
      iv1.setRange(0, 14, masterSalt);
      iv1[7] ^= 1;
      // Auth key is 20 bytes = 2 blocks
      final authBlock0 = AesCm.encrypt(masterKey, iv1, Uint8List(16));
      final iv1b = Uint8List.fromList(iv1);
      iv1b[15] = 1; // counter = 1 for second block
      final authBlock1 = AesCm.encrypt(masterKey, iv1b, Uint8List(16));
      final authKey = Uint8List(20);
      authKey.setRange(0, 16, authBlock0);
      authKey.setRange(16, 20, authBlock1.sublist(0, 4));
      expect(authKey, equals(hex('01ba9dcfc97bc080f1648441aca0e512a7faa7a4')));

      // label=2 (enc salt): salt[7] ^= 2
      final iv2 = Uint8List(16);
      iv2.setRange(0, 14, masterSalt);
      iv2[7] ^= 2;
      final encSalt = AesCm.encrypt(masterKey, iv2, Uint8List(16)).sublist(0, 14);
      expect(encSalt, equals(hex('fde65bcd987230a5fd01a1105f25')));
    });

    test('encrypt then cross-decrypt with known keys', () {
      final masterKey = hex('cbb4dbee739b8770cd9e2bc656c807ff');
      final masterSalt = hex('be1ce0813afccf2904b688a13b47');

      final km = Uint8List(60);
      km.setRange(0, 16, masterKey);
      km.setRange(32, 46, masterSalt);

      // Client encrypts
      final clientEnc = SrtpContext.fromKeyMaterial(
          keyMaterial: km, profile: SrtpProfile.aesCm128HmacSha1_80, isClient: true);
      // Server decrypts (uses client_write as remote keys)
      final serverDec = SrtpContext.fromKeyMaterial(
          keyMaterial: km, profile: SrtpProfile.aesCm128HmacSha1_80, isClient: false);

      final plainRtp = hex(
          '80ef230c6fd0c36defd852e9'
          'e5785b33ae099c44a0f4e9d7d67d7ce56c154bdefcf0bb2f24ec7fe864e6e099');

      final srtp = clientEnc.encryptRtp(plainRtp);
      expect(srtp.length, equals(54)); // 44 + 10 auth tag

      final dec = serverDec.decryptRtp(srtp);
      expect(dec.isOk, isTrue, reason: 'cross-decrypt failed: ${dec.isOk ? "" : dec.error}');
      expect(dec.value, equals(plainRtp));
    });
  });
}
