import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('Hkdf', () {
    // RFC 5869 Appendix A.1
    // Hash = SHA-256
    // IKM  = 0x0b0b...0b (22 octets)
    // salt = 0x000102...0c (13 octets)
    // info = 0xf0f1...f9 (10 octets)
    // L    = 42
    // PRK  = 0x077709366259...
    // OKM  = 0x3cb25f...

    test('RFC 5869 Appendix A.1 extract', () {
      final ikm  = Uint8List.fromList(List.filled(22, 0x0b));
      final salt = Uint8List.fromList(
          List.generate(13, (i) => i)); // 0x00..0x0c
      final prk = Hkdf.extract(salt, ikm);
      expect(prk.length, equals(32));
      // PRK = 077709366259...
      expect(prk[0], equals(0x07));
      expect(prk[1], equals(0x77));
    });

    test('RFC 5869 Appendix A.1 extract+expand', () {
      final ikm  = Uint8List.fromList(List.filled(22, 0x0b));
      final salt = Uint8List.fromList(List.generate(13, (i) => i));
      final info = Uint8List.fromList(List.generate(10, (i) => 0xf0 + i));
      final okm  = Hkdf.deriveKey(secret: ikm, salt: salt, info: info, length: 42);
      expect(okm.length, equals(42));
      // First byte of OKM from RFC 5869 Appendix A.1 = 0x3c
      expect(okm[0], equals(0x3c));
    });

    test('prfSha256 returns correct length', () {
      final secret = Uint8List.fromList('secret'.codeUnits);
      final seed   = Uint8List.fromList('seed'.codeUnits);
      final out    = Hkdf.prfSha256(secret, seed, 48);
      expect(out.length, equals(48));
    });
  });

  // RFC 8448 §3 "Simple 1-RTT Handshake" test vectors for TLS 1.3 key
  // schedule. These verify HKDF-Expand-Label and Derive-Secret behavior
  // by reproducing every secret in the published trace.
  group('Hkdf TLS 1.3 (RFC 8448 §3)', () {
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

    // SHA-256("") — the empty-string transcript hash used by Derive-Secret
    // when no messages have been sent yet (§7.1 of RFC 8446).
    final emptyHash = hex(
      'e3b0c44298fc1c149afbf4c8996fb924'
      '27ae41e4649b934ca495991b7852b855',
    );

    // (1) early_secret = HKDF-Extract(0, 0)
    final earlySecret = Hkdf.extract(Uint8List(32), Uint8List(32));
    test('early_secret', () {
      expect(
        hexOf(earlySecret),
        equals(
          '33ad0a1c607ec03b09e6cd9893680ce2'
          '10adf300aa1f2660e1b22e10f170f92a',
        ),
      );
    });

    // (2) Derive-Secret(early_secret, "derived", "")
    final derivedForHandshake = Hkdf.deriveSecret(
      secret: earlySecret,
      label: 'derived',
      transcriptHash: emptyHash,
    );
    test('derived secret for handshake', () {
      expect(
        hexOf(derivedForHandshake),
        equals(
          '6f2615a108c702c5678f54fc9dbab697'
          '16c076189c48250cebeac3576c3611ba',
        ),
      );
    });

    // (3) ECDHE shared secret from §3 (x25519 result on the wire — used
    // here as raw IKM for HKDF-Extract).
    final ecdheShared = hex(
      '8bd4054fb55b9d63fdfbacf9f04b9f0d'
      '35e6d63f537563efd46272900f89492d',
    );

    // (4) handshake_secret = HKDF-Extract(derived, ECDHE)
    final handshakeSecret = Hkdf.extract(derivedForHandshake, ecdheShared);
    test('handshake_secret', () {
      expect(
        hexOf(handshakeSecret),
        equals(
          '1dc826e93606aa6fdc0aadc12f741b01'
          '046aa6b99f691ed221a9f0ca043fbeac',
        ),
      );
    });

    // (5) transcript_hash(ClientHello, ServerHello) per RFC 8448 §3.
    final chShTranscript = hex(
      '860c06edc07858ee8e78f0e7428c58ed'
      'd6b43f2ca3e6e95f02ed063cf0e1cad8',
    );

    // (6) c_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", CH..SH)
    final cHsTraffic = Hkdf.deriveSecret(
      secret: handshakeSecret,
      label: 'c hs traffic',
      transcriptHash: chShTranscript,
    );
    test('client_handshake_traffic_secret', () {
      expect(
        hexOf(cHsTraffic),
        equals(
          'b3eddb126e067f35a780b3abf45e2d8f'
          '3b1a950738f52e9600746a0e27a55a21',
        ),
      );
    });

    // (7) s_hs_traffic = Derive-Secret(handshake_secret, "s hs traffic", CH..SH)
    final sHsTraffic = Hkdf.deriveSecret(
      secret: handshakeSecret,
      label: 's hs traffic',
      transcriptHash: chShTranscript,
    );
    test('server_handshake_traffic_secret', () {
      expect(
        hexOf(sHsTraffic),
        equals(
          'b67b7d690cc16c4e75e54213cb2d37b4'
          'e9c912bcded9105d42befd59d391ad38',
        ),
      );
    });

    // (8) handshake write keys via HKDF-Expand-Label.
    test('client handshake write key/iv', () {
      final key = Hkdf.expandLabel(
        secret: cHsTraffic,
        label: 'key',
        context: Uint8List(0),
        length: 16,
      );
      expect(
        hexOf(key),
        equals('dbfaa693d1762c5b666af5d950258d01'),
      );
      final iv = Hkdf.expandLabel(
        secret: cHsTraffic,
        label: 'iv',
        context: Uint8List(0),
        length: 12,
      );
      expect(hexOf(iv), equals('5bd3c71b836e0b76bb73265f'));
    });

    test('server handshake write key/iv', () {
      final key = Hkdf.expandLabel(
        secret: sHsTraffic,
        label: 'key',
        context: Uint8List(0),
        length: 16,
      );
      expect(
        hexOf(key),
        equals('3fce516009c21727d0f2e4e86ee403bc'),
      );
      final iv = Hkdf.expandLabel(
        secret: sHsTraffic,
        label: 'iv',
        context: Uint8List(0),
        length: 12,
      );
      expect(hexOf(iv), equals('5d313eb2671276ee13000b30'));
    });

    // (9) Derive-Secret(handshake_secret, "derived", "") feeds the master.
    final derivedForMaster = Hkdf.deriveSecret(
      secret: handshakeSecret,
      label: 'derived',
      transcriptHash: emptyHash,
    );

    // (10) master_secret = HKDF-Extract(derivedForMaster, 0)
    test('master_secret', () {
      final masterSecret = Hkdf.extract(derivedForMaster, Uint8List(32));
      expect(
        hexOf(masterSecret),
        equals(
          '18df06843d13a08bf2a449844c5f8a47'
          '8001bc4d4c627984d5a41da8d0402919',
        ),
      );
    });
  });
}
