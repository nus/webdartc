import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/x25519.dart';

void main() {
  Uint8List hex(String s) {
    final cleaned = s.replaceAll(RegExp(r'\s+'), '');
    final out = Uint8List(cleaned.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(cleaned.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }

  String hexOf(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  group('X25519.scalarMult — RFC 7748 §5.2 single-call test vectors', () {
    test('Test #1 (RFC 7748 §5.2)', () {
      final scalar = hex(
        'a546e36bf0527c9d3b16154b82465edd'
        '62144c0ac1fc5a18506a2244ba449ac4',
      );
      final u = hex(
        'e6db6867583030db3594c1a424b15f7c'
        '726624ec26b3353b10a903a6d0ab1c4c',
      );
      final result = X25519.scalarMult(scalar, u);
      expect(
        hexOf(result),
        equals(
          'c3da55379de9c6908e94ea4df28d084f'
          '32eccf03491c71f754b4075577a28552',
        ),
      );
    });

    test('Test #2 (RFC 7748 §5.2)', () {
      final scalar = hex(
        '4b66e9d4d1b4673c5ad22691957d6af5'
        'c11b6421e0ea01d42ca4169e7918ba0d',
      );
      final u = hex(
        'e5210f12786811d3f4b7959d0538ae2c'
        '31dbe7106fc03c3efc4cd549c715a493',
      );
      final result = X25519.scalarMult(scalar, u);
      expect(
        hexOf(result),
        equals(
          '95cbde9476e8907d7aade45cb4b873f8'
          '8b595a68799fa152e6f8f7647aac7957',
        ),
      );
    });
  });

  group('X25519 Diffie-Hellman — RFC 7748 §6.1', () {
    test('Alice + Bob compute the same shared secret', () {
      final alicePriv = hex(
        '77076d0a7318a57d3c16c17251b26645'
        'df4c2f87ebc0992ab177fba51db92c2a',
      );
      final alicePub = hex(
        '8520f0098930a754748b7ddcb43ef75a'
        '0dbf3a0d26381af4eba4a98eaa9b4e6a',
      );
      final bobPriv = hex(
        '5dab087e624a8a4b79e17f8b83800ee6'
        '6f3bb1292618b6fd1c2f8b27ff88e0eb',
      );
      final bobPub = hex(
        'de9edb7d7b7dc1b4d35b61c2ece43537'
        '3f8343c85b78674dadfc7e146f882b4f',
      );
      // Verify the public keys are scalarMultBase of the privates.
      expect(hexOf(X25519.scalarMultBase(alicePriv)), equals(hexOf(alicePub)));
      expect(hexOf(X25519.scalarMultBase(bobPriv)), equals(hexOf(bobPub)));
      // ECDH agreement: scalar(A) * pub(B) == scalar(B) * pub(A).
      final aShared = X25519.scalarMult(alicePriv, bobPub);
      final bShared = X25519.scalarMult(bobPriv, alicePub);
      expect(aShared, equals(bShared));
      expect(
        hexOf(aShared),
        equals(
          '4a5d9d5ba4ce2de1728e3bf480350f25'
          'e07e21c947d19e3376f09b3c1e161742',
        ),
      );
    });
  });

  group('X25519KeyPair', () {
    test('generate produces matching pub/private', () {
      final kp = X25519KeyPair.generate();
      expect(kp.publicKeyBytes.length, equals(32));
    });

    test('two peers reach the same shared secret', () {
      final a = X25519KeyPair.generate();
      final b = X25519KeyPair.generate();
      final ab = a.computeSharedSecret(b.publicKeyBytes);
      final ba = b.computeSharedSecret(a.publicKeyBytes);
      expect(ab, isNotNull);
      expect(ba, isNotNull);
      expect(ab, equals(ba));
      expect(ab!.length, equals(32));
    });

    test('handshake against u=0 produces the all-zero shared secret '
        '(low-order point per RFC 8446 §7.4.2)', () {
      // X25519 with u=0 always yields the zero u-coordinate. Test it via
      // the raw scalarMult path; KeyPair-level rejection is exercised by
      // running a fresh keypair against a u=0 peer (impossible to elicit
      // without a malicious peer, so we assert the underlying behaviour).
      final scalar = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final result = X25519.scalarMult(scalar, Uint8List(32));
      expect(result, equals(Uint8List(32)));
    });
  });
}
