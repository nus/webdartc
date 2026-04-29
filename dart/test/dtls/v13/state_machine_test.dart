import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/csprng.dart';
import 'package:webdartc/crypto/ecdh.dart';
import 'package:webdartc/crypto/ecdsa.dart';
import 'package:webdartc/crypto/hmac_sha256.dart';
import 'package:webdartc/dtls/record.dart';
import 'package:webdartc/dtls/v13/handshake.dart';
import 'package:webdartc/dtls/v13/key_schedule.dart';
import 'package:webdartc/dtls/v13/record_crypto.dart';
import 'package:webdartc/dtls/v13/state_machine.dart';
import 'package:webdartc/dtls/v13/transcript.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);

  /// Build the DTLS-form ClientHello body (no record / handshake wrapper)
  /// from a small set of fields. Matches the format webdartc's parser
  /// expects.
  Uint8List buildClientHelloBody({
    required Uint8List random,
    required List<int> cipherSuites,
    required List<TlsExtension> extensions,
    Uint8List? legacySessionId,
    Uint8List? cookie,
  }) {
    final sid = legacySessionId ?? Uint8List(0);
    final ck = cookie ?? Uint8List(0);
    final extBlock = buildTlsExtensionsBlock(extensions);
    final csTotal = cipherSuites.length * 2;
    final body = Uint8List(
      2 + 32 + 1 + sid.length + 1 + ck.length + 2 + csTotal +
          1 + 1 + extBlock.length,
    );
    var off = 0;
    body[off++] = 0xFE; body[off++] = 0xFD;
    body.setRange(off, off + 32, random); off += 32;
    body[off++] = sid.length;
    body.setRange(off, off + sid.length, sid); off += sid.length;
    body[off++] = ck.length;
    body.setRange(off, off + ck.length, ck); off += ck.length;
    body[off++] = (csTotal >> 8) & 0xFF;
    body[off++] = csTotal & 0xFF;
    for (final s in cipherSuites) {
      body[off++] = (s >> 8) & 0xFF;
      body[off++] = s & 0xFF;
    }
    body[off++] = 1; body[off++] = 0; // null compression
    body.setRange(off, off + extBlock.length, extBlock);
    return body;
  }

  /// ClientHello key_share extension data carrying a single entry.
  Uint8List buildSingleEntryKeyShareExtData({
    required int namedGroup,
    required Uint8List keyExchange,
  }) {
    final entry = buildServerHelloKeyShareExtData(
      namedGroup: namedGroup,
      keyExchange: keyExchange,
    );
    final out = Uint8List(2 + entry.length);
    out[0] = (entry.length >> 8) & 0xFF;
    out[1] =  entry.length        & 0xFF;
    out.setRange(2, out.length, entry);
    return out;
  }

  /// Wrap a handshake fragment in an epoch-0 DTLSPlaintext record (matching
  /// what a DTLS 1.3 client sends for the ClientHello).
  Uint8List wrapAsPlaintextRecord(Uint8List handshakeFragment, int seq) {
    return DtlsRecord(
      contentType: DtlsContentType.handshake,
      version: 0xFEFD,
      epoch: 0,
      sequenceNumber: seq,
      fragment: handshakeFragment,
    ).encode();
  }

  group('DtlsV13ServerStateMachine — full handshake', () {
    test('synthetic client completes the handshake to CONNECTED', () {
      final cert = EcdsaCertificate.selfSigned();
      final server = DtlsV13ServerStateMachine(localCert: cert);
      Uint8List? srtpKeyMaterial;
      server.onConnected = (km) => srtpKeyMaterial = km;

      // ── Build the synthetic ClientHello ───────────────────────────────
      final clientKp = EcdhKeyPair.generate();
      final clientRandom = Csprng.randomBytes(32);
      final chBody = buildClientHelloBody(
        random: clientRandom,
        cipherSuites: const [0x1301], // TLS_AES_128_GCM_SHA256
        extensions: [
          TlsExtension(
            TlsV13ExtensionType.supportedVersions,
            bytes([0x02, 0xFE, 0xFC]),
          ),
          TlsExtension(
            TlsV13ExtensionType.supportedGroups,
            bytes([0x00, 0x02, 0x00, 0x17]),
          ),
          TlsExtension(
            TlsV13ExtensionType.signatureAlgorithms,
            bytes([0x00, 0x02, 0x04, 0x03]),
          ),
          TlsExtension(
            TlsV13ExtensionType.keyShare,
            buildSingleEntryKeyShareExtData(
              namedGroup: TlsV13NamedGroup.secp256r1,
              keyExchange: clientKp.publicKeyBytes,
            ),
          ),
        ],
      );
      final chFull = wrapHandshake(
        msgType: TlsV13HandshakeType.clientHello,
        msgSeq: 0,
        body: chBody,
      );
      final chPacket = wrapAsPlaintextRecord(chFull, 0);

      // ── Drive the server with the ClientHello ─────────────────────────
      final r1 = server.processInput(
        chPacket,
        remoteIp: '127.0.0.1',
        remotePort: 5000,
      );
      expect(r1.isOk, isTrue,
          reason: r1.isErr ? 'unexpected error: ${r1.error}' : '');
      final flight = r1.value.outputPackets;
      // Expect: ServerHello (plaintext) + EE + Cert + CV + Fin (encrypted).
      expect(flight.length, equals(5));

      // ── Parse the plaintext ServerHello ───────────────────────────────
      final shRecord = DtlsRecord.parse(flight[0].data, 0);
      expect(shRecord, isNotNull);
      expect(shRecord!.epoch, equals(0));
      expect(shRecord.contentType, equals(DtlsContentType.handshake));

      final shHs = DtlsHandshakeHeader.parse(shRecord.fragment);
      expect(shHs, isNotNull);
      expect(shHs!.msgType, equals(TlsV13HandshakeType.serverHello));

      final sh = parseServerHelloBody(shHs.body);
      expect(sh, isNotNull);
      expect(sh!.cipherSuite, equals(0x1301));
      expect(sh.legacyVersion, equals(0xFEFD));

      Uint8List? serverPub;
      for (final e in sh.extensions) {
        if (e.type == TlsV13ExtensionType.keyShare) {
          // ServerHello form: namedGroup(2) + keyExchangeLen(2) + keyExchange.
          expect((e.data[0] << 8) | e.data[1],
              equals(TlsV13NamedGroup.secp256r1));
          final keLen = (e.data[2] << 8) | e.data[3];
          serverPub = e.data.sublist(4, 4 + keLen);
        }
        if (e.type == TlsV13ExtensionType.supportedVersions) {
          expect(e.data, equals(bytes([0xFE, 0xFC])));
        }
      }
      expect(serverPub, isNotNull);
      expect(serverPub!.length, equals(65)); // uncompressed P-256
      expect(serverPub[0], equals(0x04));

      // ── Re-derive the handshake schedule on the test side ─────────────
      final ecdhe = clientKp.computeSharedSecret(serverPub);
      final transcript = DtlsV13Transcript()
        ..addDtlsMessage(chFull)
        ..addDtlsMessage(shRecord.fragment);
      final earlySecret = TlsV13KeySchedule.computeEarlySecret();
      final hsSecret = TlsV13KeySchedule.computeHandshakeSecret(
        earlySecret: earlySecret,
        ecdheSharedSecret: ecdhe,
      );
      final chShHash = transcript.hash;
      final clientHsKeys = TlsV13KeySchedule.deriveTrafficKeys(
        trafficSecret:
            TlsV13KeySchedule.computeClientHandshakeTrafficSecret(
          handshakeSecret: hsSecret,
          chShTranscriptHash: chShHash,
        ),
        keyLength: 16,
      );
      final serverHsKeys = TlsV13KeySchedule.deriveTrafficKeys(
        trafficSecret:
            TlsV13KeySchedule.computeServerHandshakeTrafficSecret(
          handshakeSecret: hsSecret,
          chShTranscriptHash: chShHash,
        ),
        keyLength: 16,
      );

      // ── Decrypt and verify the four encrypted server messages ─────────
      final expectedMsgTypes = [
        TlsV13HandshakeType.encryptedExtensions,
        TlsV13HandshakeType.certificate,
        TlsV13HandshakeType.certificateVerify,
        TlsV13HandshakeType.finished,
      ];
      for (var i = 0; i < 4; i++) {
        final dec = DtlsV13RecordCrypto.decrypt(
          record: flight[1 + i].data,
          keys: serverHsKeys,
          epoch: 2,
          seqHi32: 0,
        );
        expect(dec, isNotNull,
            reason: 'failed to decrypt server flight record $i');
        expect(dec!.contentType, equals(DtlsContentType.handshake));
        final h = DtlsHandshakeHeader.parse(dec.content);
        expect(h, isNotNull);
        expect(h!.msgType, equals(expectedMsgTypes[i]),
            reason: 'unexpected message type at index $i');

        if (h.msgType == TlsV13HandshakeType.finished) {
          // Server's verify_data is computed before this message is added
          // to the transcript — equal to HMAC over the current transcript.
          final expected = HmacSha256.compute(
            serverHsKeys.finishedKey,
            transcript.hash,
          );
          expect(h.body, equals(expected));
        }
        transcript.addDtlsMessage(dec.content);
      }

      // ── Build and send the client's Finished ──────────────────────────
      // verify_data = HMAC(client_finished_key, transcript_through_server_Fin)
      final clientVerifyData = HmacSha256.compute(
        clientHsKeys.finishedKey,
        transcript.hash,
      );
      final clientFin = wrapHandshake(
        msgType: TlsV13HandshakeType.finished,
        msgSeq: 1,
        body: buildFinishedBody(clientVerifyData),
      );
      final clientFinRecord = DtlsV13RecordCrypto.encrypt(
        contentType: DtlsContentType.handshake,
        content: clientFin,
        epoch: 2,
        seqNum: 0,
        keys: clientHsKeys,
      );
      final r2 = server.processInput(
        clientFinRecord,
        remoteIp: '127.0.0.1',
        remotePort: 5000,
      );
      expect(r2.isOk, isTrue,
          reason: r2.isErr ? 'unexpected error: ${r2.error}' : '');

      expect(server.state, equals(DtlsV13ServerState.connected));
      expect(srtpKeyMaterial, isNotNull);
      expect(srtpKeyMaterial!.length, equals(60));
      expect(server.exporterMasterSecret, isNotNull);
      expect(server.cipherSuite!.id, equals(0x1301));
    });
  });

  group('DtlsV13ServerStateMachine — error paths', () {
    test('rejects ClientHello without supported_versions', () {
      final cert = EcdsaCertificate.selfSigned();
      final server = DtlsV13ServerStateMachine(localCert: cert);
      final body = buildClientHelloBody(
        random: Uint8List(32),
        cipherSuites: const [0x1301],
        extensions: const [], // no supported_versions
      );
      final packet = wrapAsPlaintextRecord(
        wrapHandshake(
          msgType: TlsV13HandshakeType.clientHello,
          msgSeq: 0,
          body: body,
        ),
        0,
      );
      final r = server.processInput(packet,
          remoteIp: '127.0.0.1', remotePort: 5000);
      expect(r.isErr, isTrue);
    });

    test('rejects ClientHello whose supported_versions lacks DTLS 1.3', () {
      final cert = EcdsaCertificate.selfSigned();
      final server = DtlsV13ServerStateMachine(localCert: cert);
      final body = buildClientHelloBody(
        random: Uint8List(32),
        cipherSuites: const [0x1301],
        extensions: [
          // Only DTLS 1.2 (0xFEFD)
          TlsExtension(TlsV13ExtensionType.supportedVersions,
              bytes([0x02, 0xFE, 0xFD])),
        ],
      );
      final packet = wrapAsPlaintextRecord(
        wrapHandshake(
          msgType: TlsV13HandshakeType.clientHello,
          msgSeq: 0,
          body: body,
        ),
        0,
      );
      final r = server.processInput(packet,
          remoteIp: '127.0.0.1', remotePort: 5000);
      expect(r.isErr, isTrue);
    });

    test('rejects ClientHello with no supported cipher suite', () {
      final cert = EcdsaCertificate.selfSigned();
      final server = DtlsV13ServerStateMachine(localCert: cert);
      final body = buildClientHelloBody(
        random: Uint8List(32),
        cipherSuites: const [0x1302, 0x1303], // we only support 0x1301
        extensions: [
          TlsExtension(TlsV13ExtensionType.supportedVersions,
              bytes([0x02, 0xFE, 0xFC])),
        ],
      );
      final packet = wrapAsPlaintextRecord(
        wrapHandshake(
          msgType: TlsV13HandshakeType.clientHello,
          msgSeq: 0,
          body: body,
        ),
        0,
      );
      final r = server.processInput(packet,
          remoteIp: '127.0.0.1', remotePort: 5000);
      expect(r.isErr, isTrue);
    });

    test('rejects ClientHello without a secp256r1 key_share', () {
      final cert = EcdsaCertificate.selfSigned();
      final server = DtlsV13ServerStateMachine(localCert: cert);
      final body = buildClientHelloBody(
        random: Uint8List(32),
        cipherSuites: const [0x1301],
        extensions: [
          TlsExtension(TlsV13ExtensionType.supportedVersions,
              bytes([0x02, 0xFE, 0xFC])),
          // key_share for x25519 only — server doesn't support it.
          TlsExtension(
            TlsV13ExtensionType.keyShare,
            buildSingleEntryKeyShareExtData(
              namedGroup: TlsV13NamedGroup.x25519,
              keyExchange: Uint8List(32),
            ),
          ),
        ],
      );
      final packet = wrapAsPlaintextRecord(
        wrapHandshake(
          msgType: TlsV13HandshakeType.clientHello,
          msgSeq: 0,
          body: body,
        ),
        0,
      );
      final r = server.processInput(packet,
          remoteIp: '127.0.0.1', remotePort: 5000);
      expect(r.isErr, isTrue);
    });
  });
}
