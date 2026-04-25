import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/dtls/v13/key_schedule.dart';

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

  // RFC 8448 §3 "Simple 1-RTT Handshake" trace. The transcript hashes were
  // computed independently from the on-the-wire ClientHello / ServerHello /
  // server-Finished bytes published in the RFC.

  final ecdheShared = hex(
    '8bd4054fb55b9d63fdfbacf9f04b9f0d'
    '35e6d63f537563efd46272900f89492d',
  );

  final chShHash = hex(
    '860c06edc07858ee8e78f0e7428c58ed'
    'd6b43f2ca3e6e95f02ed063cf0e1cad8',
  );

  final chSfHash = hex(
    '9608102a0f1ccc6db6250b7b7e417b1a'
    '000eaada3daae4777a7686c9ff83df13',
  );

  group('TlsV13KeySchedule (RFC 8448 §3)', () {
    test('early_secret with no PSK', () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      expect(
        hexOf(early),
        equals(
          '33ad0a1c607ec03b09e6cd9893680ce2'
          '10adf300aa1f2660e1b22e10f170f92a',
        ),
      );
    });

    test('handshake_secret = Extract(Derive(early,"derived",""), ECDHE)', () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      final hs = TlsV13KeySchedule.computeHandshakeSecret(
        earlySecret: early,
        ecdheSharedSecret: ecdheShared,
      );
      expect(
        hexOf(hs),
        equals(
          '1dc826e93606aa6fdc0aadc12f741b01'
          '046aa6b99f691ed221a9f0ca043fbeac',
        ),
      );
    });

    test('master_secret = Extract(Derive(handshake,"derived",""), 0)', () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      final hs = TlsV13KeySchedule.computeHandshakeSecret(
        earlySecret: early,
        ecdheSharedSecret: ecdheShared,
      );
      final ms = TlsV13KeySchedule.computeMasterSecret(handshakeSecret: hs);
      expect(
        hexOf(ms),
        equals(
          '18df06843d13a08bf2a449844c5f8a47'
          '8001bc4d4c627984d5a41da8d0402919',
        ),
      );
    });

    test('client/server handshake traffic secrets match the trace', () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      final hs = TlsV13KeySchedule.computeHandshakeSecret(
        earlySecret: early,
        ecdheSharedSecret: ecdheShared,
      );
      final cHs = TlsV13KeySchedule.computeClientHandshakeTrafficSecret(
        handshakeSecret: hs,
        chShTranscriptHash: chShHash,
      );
      expect(
        hexOf(cHs),
        equals(
          'b3eddb126e067f35a780b3abf45e2d8f'
          '3b1a950738f52e9600746a0e27a55a21',
        ),
      );
      final sHs = TlsV13KeySchedule.computeServerHandshakeTrafficSecret(
        handshakeSecret: hs,
        chShTranscriptHash: chShHash,
      );
      expect(
        hexOf(sHs),
        equals(
          'b67b7d690cc16c4e75e54213cb2d37b4'
          'e9c912bcded9105d42befd59d391ad38',
        ),
      );
    });

    test('client/server application traffic secrets match the trace', () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      final hs = TlsV13KeySchedule.computeHandshakeSecret(
        earlySecret: early,
        ecdheSharedSecret: ecdheShared,
      );
      final ms = TlsV13KeySchedule.computeMasterSecret(handshakeSecret: hs);

      final cAp = TlsV13KeySchedule.computeClientApplicationTrafficSecret(
        masterSecret: ms,
        chServerFinishedTranscriptHash: chSfHash,
      );
      expect(
        hexOf(cAp),
        equals(
          '9e40646ce79a7f9dc05af8889bce6552'
          '875afa0b06df0087f792ebb7c17504a5',
        ),
      );
      final sAp = TlsV13KeySchedule.computeServerApplicationTrafficSecret(
        masterSecret: ms,
        chServerFinishedTranscriptHash: chSfHash,
      );
      expect(
        hexOf(sAp),
        equals(
          'a11af9f05531f856ad47116b45a95032'
          '8204b4f44bfb6b3a4b4f1f3fcb631643',
        ),
      );
    });

    test('exporter_master_secret matches the trace', () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      final hs = TlsV13KeySchedule.computeHandshakeSecret(
        earlySecret: early,
        ecdheSharedSecret: ecdheShared,
      );
      final ms = TlsV13KeySchedule.computeMasterSecret(handshakeSecret: hs);
      final exp = TlsV13KeySchedule.computeExporterMasterSecret(
        masterSecret: ms,
        chServerFinishedTranscriptHash: chSfHash,
      );
      expect(
        hexOf(exp),
        equals(
          'fe22f881176eda18eb8f44529e6792c5'
          '0c9a3f89452f68d8ae311b4309d3cf50',
        ),
      );
    });

    test('deriveTrafficKeys yields RFC 8448 client handshake key/iv', () {
      // c_hs_traffic from RFC 8448 §3.
      final cHs = hex(
        'b3eddb126e067f35a780b3abf45e2d8f'
        '3b1a950738f52e9600746a0e27a55a21',
      );
      final keys = TlsV13KeySchedule.deriveTrafficKeys(
        trafficSecret: cHs,
        keyLength: 16, // AES-128
      );
      expect(hexOf(keys.writeKey), equals('dbfaa693d1762c5b666af5d950258d01'));
      expect(hexOf(keys.writeIv), equals('5bd3c71b836e0b76bb73265f'));
      // finished_key is HashLen = 32 bytes for SHA-256.
      expect(keys.finishedKey.length, equals(32));
      // sn_key is keyLength bytes for AES-based sequence number protection.
      expect(keys.snKey.length, equals(16));
    });

    test('deriveTrafficKeys yields RFC 8448 server handshake key/iv', () {
      final sHs = hex(
        'b67b7d690cc16c4e75e54213cb2d37b4'
        'e9c912bcded9105d42befd59d391ad38',
      );
      final keys = TlsV13KeySchedule.deriveTrafficKeys(
        trafficSecret: sHs,
        keyLength: 16,
      );
      expect(hexOf(keys.writeKey), equals('3fce516009c21727d0f2e4e86ee403bc'));
      expect(hexOf(keys.writeIv), equals('5d313eb2671276ee13000b30'));
    });
  });
}
