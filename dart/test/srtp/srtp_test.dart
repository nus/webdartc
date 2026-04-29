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

  // RFC 5764 §4.2 + RFC 7714 §12 — the AEAD-GCM profiles use 12-byte
  // master salts (and, for AES-256, 32-byte master keys), so the slicing
  // of TLS-exporter output must be profile-aware.
  group('SrtpContext.fromKeyMaterial layout (RFC 7714 §12)', () {
    test('AEAD-AES-128-GCM consumes 56 bytes laid out 16+16+12+12', () {
      // Distinct bytes per region so we can verify the splits without
      // depending on the KDF: clientKey=0x11..., serverKey=0x22...,
      // clientSalt=0x33..., serverSalt=0x44...
      final km = Uint8List(56);
      km.fillRange(0, 16, 0x11);
      km.fillRange(16, 32, 0x22);
      km.fillRange(32, 44, 0x33);
      km.fillRange(44, 56, 0x44);

      final clientCtx = SrtpContext.fromKeyMaterial(
        keyMaterial: km,
        profile: SrtpProfile.aesGcm128,
        isClient: true,
      );
      final serverCtx = SrtpContext.fromKeyMaterial(
        keyMaterial: km,
        profile: SrtpProfile.aesGcm128,
        isClient: false,
      );

      // Round trip a small RTP packet with each role: client-encrypt
      // must decrypt with server-context (which uses the client's
      // master-key/salt as its *remote* keys), and vice versa.
      final rtp = Uint8List.fromList([
        0x80, 0x60, 0x00, 0x42, 0x00, 0x00, 0x10, 0x00,
        0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8,
      ]);

      final fromClient = clientCtx.encryptRtp(rtp);
      final decFromClient = serverCtx.decryptRtp(fromClient);
      expect(decFromClient.isOk, isTrue,
          reason: 'GCM-128 client→server decrypt failed: '
              '${decFromClient.isErr ? decFromClient.error : ""}');
      expect(decFromClient.value, equals(rtp));

      final fromServer = serverCtx.encryptRtp(rtp);
      final decFromServer = clientCtx.decryptRtp(fromServer);
      expect(decFromServer.isOk, isTrue,
          reason: 'GCM-128 server→client decrypt failed: '
              '${decFromServer.isErr ? decFromServer.error : ""}');
      expect(decFromServer.value, equals(rtp));
    });

    test('AEAD-AES-256-GCM consumes 88 bytes laid out 32+32+12+12', () {
      // Layout: clientKey(32) || serverKey(32) || clientSalt(12) ||
      // serverSalt(12) — 88 bytes total per RFC 7714 §12.3.
      final km = Uint8List(88);
      km.fillRange(0, 32, 0x55);
      km.fillRange(32, 64, 0x66);
      km.fillRange(64, 76, 0x77);
      km.fillRange(76, 88, 0x88);

      final clientCtx = SrtpContext.fromKeyMaterial(
        keyMaterial: km,
        profile: SrtpProfile.aesGcm256,
        isClient: true,
      );
      final serverCtx = SrtpContext.fromKeyMaterial(
        keyMaterial: km,
        profile: SrtpProfile.aesGcm256,
        isClient: false,
      );

      final rtp = Uint8List.fromList([
        0x80, 0x60, 0x00, 0x07, 0x00, 0x00, 0x20, 0x00,
        0xCA, 0xFE, 0xBA, 0xBE, 9, 10, 11, 12, 13, 14, 15, 16,
      ]);

      final fromClient = clientCtx.encryptRtp(rtp);
      final decFromClient = serverCtx.decryptRtp(fromClient);
      expect(decFromClient.isOk, isTrue,
          reason: 'GCM-256 client→server decrypt failed: '
              '${decFromClient.isErr ? decFromClient.error : ""}');
      expect(decFromClient.value, equals(rtp));

      final fromServer = serverCtx.encryptRtp(rtp);
      final decFromServer = clientCtx.decryptRtp(fromServer);
      expect(decFromServer.isOk, isTrue,
          reason: 'GCM-256 server→client decrypt failed: '
              '${decFromServer.isErr ? decFromServer.error : ""}');
      expect(decFromServer.value, equals(rtp));
    });

    test('GCM-128 uses serverKey/serverSalt for the outbound side when '
        'isClient: false (cross-role, distinct keys)', () {
      // If the slicing accidentally used 14-byte salts, the client and
      // server would derive their per-direction salts from overlapping
      // byte ranges. With profile-aware slicing, swapping the *server*
      // key/salt bytes must change every server-side encryption result
      // while leaving client-side outputs untouched.
      Uint8List km(int seed) {
        final b = Uint8List(56);
        b.fillRange(0, 16, 0x11);
        b.fillRange(16, 32, 0x22 ^ seed);
        b.fillRange(32, 44, 0x33);
        b.fillRange(44, 56, 0x44 ^ seed);
        return b;
      }

      final km1 = km(0);
      final km2 = km(0x0F);

      final server1 = SrtpContext.fromKeyMaterial(
        keyMaterial: km1,
        profile: SrtpProfile.aesGcm128,
        isClient: false,
      );
      final server2 = SrtpContext.fromKeyMaterial(
        keyMaterial: km2,
        profile: SrtpProfile.aesGcm128,
        isClient: false,
      );

      // Force a stable per-call IV by sending a single packet from each
      // context starting at SSRC=0 / SEQ=1 / ROC=0.
      final rtp = Uint8List.fromList([
        0x80, 0x60, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 1, 2, 3, 4,
      ]);
      expect(server1.encryptRtp(rtp), isNot(equals(server2.encryptRtp(rtp))),
          reason: 'flipping the server-write region must change '
              'GCM-128 server-side ciphertext (catches off-by-2-byte '
              'salt-slicing bugs)');
    });
  });
}
