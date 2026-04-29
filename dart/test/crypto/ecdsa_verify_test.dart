import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/ecdsa.dart';
import 'package:webdartc/crypto/x509_der.dart';

void main() {
  group('EcdsaVerify.verifyP256Sha256', () {
    test('accepts a fresh signature from EcdsaCertificate.sign', () {
      final cert = EcdsaCertificate.selfSigned();
      final pub = extractEcdsaP256PublicKey(cert.derBytes)!;
      final msg = Uint8List.fromList(List<int>.generate(128, (i) => i & 0xFF));
      final sig = cert.sign(msg);
      expect(
        EcdsaVerify.verifyP256Sha256(
          publicKey: pub,
          message: msg,
          signature: sig,
        ),
        isTrue,
      );
    });

    test('rejects a tampered signature', () {
      final cert = EcdsaCertificate.selfSigned();
      final pub = extractEcdsaP256PublicKey(cert.derBytes)!;
      final msg = Uint8List.fromList([1, 2, 3, 4, 5]);
      final sig = Uint8List.fromList(cert.sign(msg));
      sig[sig.length - 1] ^= 0x01;
      expect(
        EcdsaVerify.verifyP256Sha256(
          publicKey: pub,
          message: msg,
          signature: sig,
        ),
        isFalse,
      );
    });

    test('rejects a tampered message', () {
      final cert = EcdsaCertificate.selfSigned();
      final pub = extractEcdsaP256PublicKey(cert.derBytes)!;
      final msg = Uint8List.fromList([1, 2, 3, 4, 5]);
      final sig = cert.sign(msg);
      final tamperedMsg = Uint8List.fromList(msg);
      tamperedMsg[0] ^= 0x01;
      expect(
        EcdsaVerify.verifyP256Sha256(
          publicKey: pub,
          message: tamperedMsg,
          signature: sig,
        ),
        isFalse,
      );
    });

    test('rejects a signature verified against the wrong public key', () {
      final certA = EcdsaCertificate.selfSigned();
      final certB = EcdsaCertificate.selfSigned();
      final pubB = extractEcdsaP256PublicKey(certB.derBytes)!;
      final msg = Uint8List.fromList([9, 8, 7, 6]);
      final sig = certA.sign(msg);
      expect(
        EcdsaVerify.verifyP256Sha256(
          publicKey: pubB,
          message: msg,
          signature: sig,
        ),
        isFalse,
      );
    });
  });

  group('extractEcdsaP256PublicKey', () {
    test('round-trips with EcdsaCertificate.selfSigned (200 trials)', () {
      for (var i = 0; i < 200; i++) {
        final cert = EcdsaCertificate.selfSigned();
        final pub = extractEcdsaP256PublicKey(cert.derBytes);
        expect(pub, isNotNull, reason: 'trial $i: extraction returned null');
        expect(pub!.length, equals(65),
            reason: 'trial $i: expected 65-byte uncompressed point');
        expect(pub[0], equals(0x04),
            reason: 'trial $i: expected 0x04 prefix');
        // Sanity: a fresh signature from this cert verifies against its
        // extracted pubkey.
        final msg = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
        final sig = cert.sign(msg);
        expect(
          EcdsaVerify.verifyP256Sha256(
            publicKey: pub,
            message: msg,
            signature: sig,
          ),
          isTrue,
          reason: 'trial $i: verify(sign(...)) failed',
        );
      }
    });

    test('returns null for non-DER input', () {
      expect(extractEcdsaP256PublicKey(Uint8List(0)), isNull);
      expect(extractEcdsaP256PublicKey(Uint8List.fromList([1, 2, 3])), isNull);
    });
  });
}
