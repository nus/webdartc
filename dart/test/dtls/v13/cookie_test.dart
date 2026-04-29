import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/csprng.dart';
import 'package:webdartc/crypto/sha256.dart';
import 'package:webdartc/dtls/v13/cookie.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);

  group('DtlsV13Cookie', () {
    final macKey = Csprng.randomBytes(32);
    final transcriptHash = Uint8List.fromList(
      List<int>.generate(32, (i) => 0xA0 ^ i),
    );

    test('mint produces a 65-byte v1 cookie carrying the transcript hash',
        () {
      final cookie = DtlsV13Cookie.mint(
        macKey: macKey,
        transcriptHashCh1: transcriptHash,
        clientIp: '127.0.0.1',
        clientPort: 5000,
      );
      expect(cookie.length, equals(DtlsV13Cookie.byteLength));
      expect(cookie[0], equals(DtlsV13Cookie.versionByte));
      expect(cookie.sublist(1, 33), equals(transcriptHash));
    });

    test('open recovers the transcript hash and validates HMAC', () {
      final cookie = DtlsV13Cookie.mint(
        macKey: macKey,
        transcriptHashCh1: transcriptHash,
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      final opened = DtlsV13Cookie.open(
        macKey: macKey,
        cookie: cookie,
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      expect(opened, isNotNull);
      expect(opened!.isValid, isTrue);
      expect(opened.transcriptHashCh1, equals(transcriptHash));
    });

    test('open rejects a cookie minted under a different macKey', () {
      final cookie = DtlsV13Cookie.mint(
        macKey: macKey,
        transcriptHashCh1: transcriptHash,
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      final foreignKey = Csprng.randomBytes(32);
      final opened = DtlsV13Cookie.open(
        macKey: foreignKey,
        cookie: cookie,
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      expect(opened, isNotNull); // structurally well-formed
      expect(opened!.isValid, isFalse);
    });

    test('open rejects replay from a different ip', () {
      final cookie = DtlsV13Cookie.mint(
        macKey: macKey,
        transcriptHashCh1: transcriptHash,
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      final opened = DtlsV13Cookie.open(
        macKey: macKey,
        cookie: cookie,
        clientIp: '10.0.0.2', // attacker IP
        clientPort: 12345,
      );
      expect(opened!.isValid, isFalse);
    });

    test('open rejects replay from a different port', () {
      final cookie = DtlsV13Cookie.mint(
        macKey: macKey,
        transcriptHashCh1: transcriptHash,
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      final opened = DtlsV13Cookie.open(
        macKey: macKey,
        cookie: cookie,
        clientIp: '10.0.0.1',
        clientPort: 1, // wrong port
      );
      expect(opened!.isValid, isFalse);
    });

    test('open returns null for cookies of the wrong size', () {
      final opened = DtlsV13Cookie.open(
        macKey: macKey,
        cookie: bytes(List<int>.filled(64, 1)),
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      expect(opened, isNull);
    });

    test('open returns null for an unknown version byte', () {
      final cookie = DtlsV13Cookie.mint(
        macKey: macKey,
        transcriptHashCh1: transcriptHash,
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      cookie[0] = 0x02; // bump version
      final opened = DtlsV13Cookie.open(
        macKey: macKey,
        cookie: cookie,
        clientIp: '10.0.0.1',
        clientPort: 12345,
      );
      expect(opened, isNull);
    });

    test('mint rejects a non-32-byte transcript hash', () {
      expect(
        () => DtlsV13Cookie.mint(
          macKey: macKey,
          transcriptHashCh1: Uint8List(31),
          clientIp: '10.0.0.1',
          clientPort: 12345,
        ),
        throwsArgumentError,
      );
    });

    test('mint rejects an out-of-range port', () {
      expect(
        () => DtlsV13Cookie.mint(
          macKey: macKey,
          transcriptHashCh1: transcriptHash,
          clientIp: '10.0.0.1',
          clientPort: 70000,
        ),
        throwsArgumentError,
      );
    });

    test('digestLength matches Sha256 (sanity check)', () {
      // The cookie format hard-codes 32 bytes — confirm that's still
      // SHA-256's output size in case the crypto module ever changes.
      expect(Sha256.digestLength, equals(32));
    });
  });
}
