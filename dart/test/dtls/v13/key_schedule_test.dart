import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/hkdf.dart';
import 'package:webdartc/crypto/sha256.dart';
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

  // Inputs derived from the RFC 8448 §3 trace. We can't reuse the published
  // *output* values because RFC 8448 uses the TLS 1.3 HKDF prefix ("tls13 ")
  // while DTLS 1.3 uses "dtls13" (RFC 9147 §5.9), so the schedule outputs
  // diverge starting from the very first Derive-Secret. Inputs (ECDHE
  // shared secret, transcript hashes) are independent of that prefix and
  // remain useful as plausible non-trivial values.

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

  final emptyHash = Sha256.hash(Uint8List(0));

  Uint8List dtlsExpand({
    required Uint8List secret,
    required String label,
    required Uint8List context,
    int length = 32,
  }) =>
      Hkdf.expandLabel(
        secret: secret,
        label: label,
        context: context,
        length: length,
        prefix: Hkdf.dtls13Prefix,
      );

  group('TlsV13KeySchedule — early/handshake/master secrets', () {
    test('early_secret with no PSK matches RFC 8448 (Extract is prefix-free)',
        () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      // HKDF-Extract has no protocol prefix, so this value is identical for
      // TLS 1.3 and DTLS 1.3.
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
      // Reproduce the schedule manually with the DTLS 1.3 prefix and
      // confirm bit-for-bit agreement.
      final derived = dtlsExpand(
        secret: early,
        label: 'derived',
        context: emptyHash,
      );
      final expected = Hkdf.extract(derived, ecdheShared);
      expect(hexOf(hs), equals(hexOf(expected)));
    });

    test('master_secret = Extract(Derive(handshake,"derived",""), 0)', () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      final hs = TlsV13KeySchedule.computeHandshakeSecret(
        earlySecret: early,
        ecdheSharedSecret: ecdheShared,
      );
      final ms = TlsV13KeySchedule.computeMasterSecret(handshakeSecret: hs);
      final derived = dtlsExpand(
        secret: hs,
        label: 'derived',
        context: emptyHash,
      );
      final expected = Hkdf.extract(derived, Uint8List(32));
      expect(hexOf(ms), equals(hexOf(expected)));
    });
  });

  group('TlsV13KeySchedule — traffic secrets', () {
    test('client/server handshake traffic secrets match a hand derivation',
        () {
      final early = TlsV13KeySchedule.computeEarlySecret();
      final hs = TlsV13KeySchedule.computeHandshakeSecret(
        earlySecret: early,
        ecdheSharedSecret: ecdheShared,
      );
      final cHs = TlsV13KeySchedule.computeClientHandshakeTrafficSecret(
        handshakeSecret: hs,
        chShTranscriptHash: chShHash,
      );
      final sHs = TlsV13KeySchedule.computeServerHandshakeTrafficSecret(
        handshakeSecret: hs,
        chShTranscriptHash: chShHash,
      );
      expect(
        hexOf(cHs),
        equals(hexOf(dtlsExpand(
          secret: hs,
          label: 'c hs traffic',
          context: chShHash,
        ))),
      );
      expect(
        hexOf(sHs),
        equals(hexOf(dtlsExpand(
          secret: hs,
          label: 's hs traffic',
          context: chShHash,
        ))),
      );
    });

    test('client/server application traffic secrets match a hand derivation',
        () {
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
      final sAp = TlsV13KeySchedule.computeServerApplicationTrafficSecret(
        masterSecret: ms,
        chServerFinishedTranscriptHash: chSfHash,
      );
      expect(
        hexOf(cAp),
        equals(hexOf(dtlsExpand(
          secret: ms,
          label: 'c ap traffic',
          context: chSfHash,
        ))),
      );
      expect(
        hexOf(sAp),
        equals(hexOf(dtlsExpand(
          secret: ms,
          label: 's ap traffic',
          context: chSfHash,
        ))),
      );
    });

    test('exporter_master_secret matches a hand derivation', () {
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
        equals(hexOf(dtlsExpand(
          secret: ms,
          label: 'exp master',
          context: chSfHash,
        ))),
      );
    });
  });

  group('TlsV13KeySchedule.deriveTrafficKeys (RFC 9147 §5.9)', () {
    test('uses the "dtls13" HKDF prefix for key/iv/finished/sn', () {
      final secret = Uint8List.fromList(
        List<int>.generate(32, (i) => 0xA0 ^ i),
      );
      final keys = TlsV13KeySchedule.deriveTrafficKeys(
        trafficSecret: secret,
        keyLength: 16,
      );
      // Compute expected values manually with the DTLS prefix and compare.
      expect(
        keys.writeKey,
        equals(dtlsExpand(
          secret: secret,
          label: 'key',
          context: Uint8List(0),
          length: 16,
        )),
      );
      expect(
        keys.writeIv,
        equals(dtlsExpand(
          secret: secret,
          label: 'iv',
          context: Uint8List(0),
          length: 12,
        )),
      );
      expect(
        keys.finishedKey,
        equals(dtlsExpand(
          secret: secret,
          label: 'finished',
          context: Uint8List(0),
          length: 32,
        )),
      );
      expect(
        keys.snKey,
        equals(dtlsExpand(
          secret: secret,
          label: 'sn',
          context: Uint8List(0),
          length: 16,
        )),
      );
    });

    test('outputs differ from a TLS-1.3-prefixed derivation', () {
      // Sanity: prove that the prefix change actually produces different
      // bytes — guards against accidentally falling back to the TLS prefix.
      final secret = Uint8List.fromList(
        List<int>.generate(32, (i) => 0xA0 ^ i),
      );
      final keys = TlsV13KeySchedule.deriveTrafficKeys(
        trafficSecret: secret,
        keyLength: 16,
      );
      final tlsKey = Hkdf.expandLabel(
        secret: secret,
        label: 'key',
        context: Uint8List(0),
        length: 16,
        // default prefix = "tls13 "
      );
      expect(keys.writeKey, isNot(equals(tlsKey)));
    });
  });
}
