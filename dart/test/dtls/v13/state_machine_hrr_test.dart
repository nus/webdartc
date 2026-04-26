// HelloRetryRequest path through DtlsV13ServerStateMachine.
//
// Drives a synthetic client that initially key_shares an unsupported
// group (secp521r1) but lists secp256r1 in supported_groups; the server
// must respond with a HRR demanding secp256r1, and the synthetic client
// then resubmits a CH2 carrying both the new key_share and the cookie
// echo. The handshake should reach CONNECTED on the second round trip.

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

  Uint8List buildClientHelloBody({
    required Uint8List random,
    required List<int> cipherSuites,
    required List<TlsExtension> extensions,
  }) {
    final extBlock = buildTlsExtensionsBlock(extensions);
    final csTotal = cipherSuites.length * 2;
    final body = Uint8List(
      2 + 32 + 1 + 1 + 2 + csTotal + 1 + 1 + extBlock.length,
    );
    var off = 0;
    body[off++] = 0xFE; body[off++] = 0xFD;
    body.setRange(off, off + 32, random); off += 32;
    body[off++] = 0; // session_id length
    body[off++] = 0; // cookie length
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

  Uint8List singleEntryKeyShare({
    required int namedGroup,
    required Uint8List keyExchange,
  }) {
    final entry = buildServerHelloKeyShareExtData(
      namedGroup: namedGroup,
      keyExchange: keyExchange,
    );
    final out = Uint8List(2 + entry.length);
    out[0] = (entry.length >> 8) & 0xFF;
    out[1] = entry.length & 0xFF;
    out.setRange(2, out.length, entry);
    return out;
  }

  Uint8List wrapAsPlaintext(Uint8List handshakeFragment, {int seq = 0}) {
    return DtlsRecord(
      contentType: DtlsContentType.handshake,
      version: 0xFEFD,
      epoch: 0,
      sequenceNumber: seq,
      fragment: handshakeFragment,
    ).encode();
  }

  test('HRR fills in a missing secp256r1 key_share and the handshake completes',
      () {
    final cert = EcdsaCertificate.selfSigned();
    final server = DtlsV13ServerStateMachine(localCert: cert);
    Uint8List? srtpKeyMaterial;
    server.onConnected = (km) => srtpKeyMaterial = km;

    final clientRandom = Csprng.randomBytes(32);

    // ── CH1: supported_groups lists secp256r1 + secp521r1 but key_share
    //         only carries an (unsupported) secp521r1 entry ──────────────
    const secp521r1 = 0x0019;
    final ch1Body = buildClientHelloBody(
      random: clientRandom,
      cipherSuites: const [0x1301],
      extensions: [
        TlsExtension(
          TlsV13ExtensionType.supportedVersions,
          bytes([0x02, 0xFE, 0xFC]),
        ),
        TlsExtension(
          TlsV13ExtensionType.supportedGroups,
          // length=4: secp521r1 (0x0019), secp256r1 (0x0017)
          bytes([0x00, 0x04, 0x00, 0x19, 0x00, 0x17]),
        ),
        TlsExtension(
          TlsV13ExtensionType.signatureAlgorithms,
          bytes([0x00, 0x02, 0x04, 0x03]),
        ),
        TlsExtension(
          TlsV13ExtensionType.keyShare,
          singleEntryKeyShare(
            namedGroup: secp521r1,
            // 133-byte fake P-521 point — content doesn't matter, the
            // server should reject it as an unsupported group anyway.
            keyExchange: Uint8List(133)..[0] = 0x04,
          ),
        ),
      ],
    );
    final ch1Full = wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: 0,
      body: ch1Body,
    );
    final ch1Packet = wrapAsPlaintext(ch1Full);

    final r1 = server.processInput(ch1Packet,
        remoteIp: '127.0.0.1', remotePort: 5000);
    expect(r1.isOk, isTrue,
        reason: r1.isErr ? '${r1.error}' : '');
    final hrrPackets = r1.value.outputPackets;
    expect(hrrPackets.length, equals(1),
        reason: 'HRR is a single plaintext record');

    // Parse the HRR back. Verify the sentinel random and required
    // extensions (supported_versions, key_share with selected_group only,
    // cookie).
    final hrrRec = DtlsRecord.parse(hrrPackets[0].data, 0)!;
    expect(hrrRec.epoch, equals(0));
    final hrrHs = DtlsHandshakeHeader.parse(hrrRec.fragment)!;
    expect(hrrHs.msgType, equals(TlsV13HandshakeType.serverHello));
    final sh = parseServerHelloBody(hrrHs.body)!;
    expect(sh.random, equals(helloRetryRequestRandom));
    expect(sh.cipherSuite, equals(0x1301));

    int? chosenGroup;
    Uint8List? cookieFromHrr;
    for (final e in sh.extensions) {
      if (e.type == TlsV13ExtensionType.keyShare) {
        chosenGroup = parseHrrKeyShareExtData(e.data);
      } else if (e.type == TlsV13ExtensionType.cookie) {
        cookieFromHrr = parseCookieExtData(e.data);
      }
    }
    expect(chosenGroup, equals(TlsV13NamedGroup.secp256r1));
    expect(cookieFromHrr, isNotNull);
    // Stateless cookie format (RFC 9147 §5.1): 1B version + 32B
    // transcript hash + 32B HMAC tag = 65 bytes.
    expect(cookieFromHrr!.length, equals(65));

    // ── CH2: now carry a secp256r1 key_share + the cookie echo ─────────
    final clientKp = EcdhKeyPair.generate();
    final ch2Body = buildClientHelloBody(
      random: clientRandom, // same client_random as CH1
      cipherSuites: const [0x1301],
      extensions: [
        TlsExtension(
          TlsV13ExtensionType.supportedVersions,
          bytes([0x02, 0xFE, 0xFC]),
        ),
        TlsExtension(
          TlsV13ExtensionType.supportedGroups,
          bytes([0x00, 0x04, 0x00, 0x19, 0x00, 0x17]),
        ),
        TlsExtension(
          TlsV13ExtensionType.signatureAlgorithms,
          bytes([0x00, 0x02, 0x04, 0x03]),
        ),
        TlsExtension(
          TlsV13ExtensionType.keyShare,
          singleEntryKeyShare(
            namedGroup: TlsV13NamedGroup.secp256r1,
            keyExchange: clientKp.publicKeyBytes,
          ),
        ),
        TlsExtension(
          TlsV13ExtensionType.cookie,
          buildCookieExtData(cookieFromHrr),
        ),
      ],
    );
    final ch2Full = wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: 1, // RFC 9147 §5.2: msg_seq advances on retry
      body: ch2Body,
    );
    final ch2Packet = wrapAsPlaintext(ch2Full, seq: 1);

    final r2 = server.processInput(ch2Packet,
        remoteIp: '127.0.0.1', remotePort: 5000);
    expect(r2.isOk, isTrue,
        reason: r2.isErr ? '${r2.error}' : '');
    final flight = r2.value.outputPackets;
    expect(flight.length, equals(5),
        reason: 'CH2 should elicit ServerHello + EE + Cert + CV + Fin');

    // Parse SH (real one this time — different random than the sentinel).
    final shRecord = DtlsRecord.parse(flight[0].data, 0)!;
    final shHs = DtlsHandshakeHeader.parse(shRecord.fragment)!;
    expect(shHs.msgType, equals(TlsV13HandshakeType.serverHello));
    final realSh = parseServerHelloBody(shHs.body)!;
    expect(realSh.random, isNot(equals(helloRetryRequestRandom)));

    // Pull server's secp256r1 public key out of the SH key_share.
    Uint8List? serverPub;
    for (final e in realSh.extensions) {
      if (e.type == TlsV13ExtensionType.keyShare) {
        final keLen = (e.data[2] << 8) | e.data[3];
        serverPub = e.data.sublist(4, 4 + keLen);
      }
    }
    expect(serverPub, isNotNull);

    // ── Reproduce the schedule on the synthetic client side. The CH..SH
    //    transcript on this path is `synthetic(CH1) || HRR || CH2 || SH`. ──
    final chSyntheticHash = (DtlsV13Transcript()..addDtlsMessage(ch1Full)).hash;
    final synthetic = Uint8List(4 + 32)
      ..[0] = 0xFE
      ..[1] = 0x00
      ..[2] = 0x00
      ..[3] = 0x20
      ..setRange(4, 4 + 32, chSyntheticHash);
    final transcript = DtlsV13Transcript()
      ..addRawTlsMessage(synthetic)
      ..addDtlsMessage(hrrRec.fragment)
      ..addDtlsMessage(ch2Full)
      ..addDtlsMessage(shRecord.fragment);

    final ecdhe = clientKp.computeSharedSecret(serverPub!);
    final earlySecret = TlsV13KeySchedule.computeEarlySecret();
    final hsSecret = TlsV13KeySchedule.computeHandshakeSecret(
      earlySecret: earlySecret,
      ecdheSharedSecret: ecdhe,
    );
    final clientHsKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: TlsV13KeySchedule.computeClientHandshakeTrafficSecret(
        handshakeSecret: hsSecret,
        chShTranscriptHash: transcript.hash,
      ),
      keyLength: 16,
    );
    final serverHsKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: TlsV13KeySchedule.computeServerHandshakeTrafficSecret(
        handshakeSecret: hsSecret,
        chShTranscriptHash: transcript.hash,
      ),
      keyLength: 16,
    );

    // Decrypt the four encrypted handshake records, verify ordering, and
    // accumulate them into the client-side transcript.
    const expected = [
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
      );
      expect(dec, isNotNull, reason: 'failed to decrypt server flight[$i]');
      expect(dec!.contentType, equals(DtlsContentType.handshake));
      final h = DtlsHandshakeHeader.parse(dec.content)!;
      expect(h.msgType, equals(expected[i]));
      transcript.addDtlsMessage(dec.content);
    }

    // Send the client's Finished and confirm the server reaches CONNECTED.
    final clientVerifyData = HmacSha256.compute(
      clientHsKeys.finishedKey,
      transcript.hash,
    );
    final clientFin = wrapHandshake(
      msgType: TlsV13HandshakeType.finished,
      msgSeq: 2,
      body: buildFinishedBody(clientVerifyData),
    );
    final clientFinRecord = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.handshake,
      content: clientFin,
      epoch: 2,
      seqNum: 0,
      keys: clientHsKeys,
    );
    final r3 = server.processInput(
      clientFinRecord,
      remoteIp: '127.0.0.1',
      remotePort: 5000,
    );
    expect(r3.isOk, isTrue);
    expect(server.state, equals(DtlsV13ServerState.connected));
    expect(server.exporterMasterSecret, isNotNull);
    // onConnected always exports a 60-byte SRTP keying-material block, even
    // when use_srtp wasn't negotiated — matches the DTLS 1.2 path so the
    // upper layer can build the SrtpContext uniformly.
    expect(srtpKeyMaterial, isNotNull);
    expect(srtpKeyMaterial!.length, equals(60));
  });

  test('HRR is rejected when CH2 echoes the wrong cookie', () {
    final cert = EcdsaCertificate.selfSigned();
    final server = DtlsV13ServerStateMachine(localCert: cert);

    final clientRandom = Csprng.randomBytes(32);
    const secp521r1 = 0x0019;
    final ch1Body = buildClientHelloBody(
      random: clientRandom,
      cipherSuites: const [0x1301],
      extensions: [
        TlsExtension(
          TlsV13ExtensionType.supportedVersions,
          bytes([0x02, 0xFE, 0xFC]),
        ),
        TlsExtension(
          TlsV13ExtensionType.supportedGroups,
          bytes([0x00, 0x04, 0x00, 0x19, 0x00, 0x17]),
        ),
        TlsExtension(
          TlsV13ExtensionType.keyShare,
          singleEntryKeyShare(
            namedGroup: secp521r1,
            keyExchange: Uint8List(133)..[0] = 0x04,
          ),
        ),
      ],
    );
    final ch1Full = wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: 0,
      body: ch1Body,
    );
    server.processInput(wrapAsPlaintext(ch1Full),
        remoteIp: '127.0.0.1', remotePort: 5000);
    expect(server.state, equals(DtlsV13ServerState.waitSecondClientHello));

    // CH2 with bogus cookie.
    final clientKp = EcdhKeyPair.generate();
    final ch2Body = buildClientHelloBody(
      random: clientRandom,
      cipherSuites: const [0x1301],
      extensions: [
        TlsExtension(
          TlsV13ExtensionType.supportedVersions,
          bytes([0x02, 0xFE, 0xFC]),
        ),
        TlsExtension(
          TlsV13ExtensionType.supportedGroups,
          bytes([0x00, 0x04, 0x00, 0x19, 0x00, 0x17]),
        ),
        TlsExtension(
          TlsV13ExtensionType.keyShare,
          singleEntryKeyShare(
            namedGroup: TlsV13NamedGroup.secp256r1,
            keyExchange: clientKp.publicKeyBytes,
          ),
        ),
        TlsExtension(
          TlsV13ExtensionType.cookie,
          buildCookieExtData(Uint8List(32)), // all-zero ≠ random cookie
        ),
      ],
    );
    final ch2Full = wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: 1,
      body: ch2Body,
    );
    final r2 = server.processInput(
      wrapAsPlaintext(ch2Full, seq: 1),
      remoteIp: '127.0.0.1',
      remotePort: 5000,
    );
    expect(r2.isErr, isTrue);
  });
}
