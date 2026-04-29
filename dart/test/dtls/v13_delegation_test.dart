// Verifies that the legacy [DtlsStateMachine] (v1.2) class transparently
// delegates to [DtlsV13ServerStateMachine] when a DTLS 1.3 ClientHello
// arrives in server mode. This is the integration path PeerConnection
// uses today: callers don't need to know about v1.3 explicitly.

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/core/state_machine.dart';
import 'package:webdartc/crypto/csprng.dart';
import 'package:webdartc/crypto/ecdh.dart';
import 'package:webdartc/crypto/ecdsa.dart';
import 'package:webdartc/crypto/hmac_sha256.dart';
import 'package:webdartc/dtls/record.dart';
import 'package:webdartc/dtls/state_machine.dart';
import 'package:webdartc/dtls/v13/handshake.dart';
import 'package:webdartc/dtls/v13/key_schedule.dart';
import 'package:webdartc/dtls/v13/record_crypto.dart';
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
    body[off++] = 1; body[off++] = 0;
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

  Uint8List wrapAsPlaintext(Uint8List handshakeFragment) {
    return DtlsRecord(
      contentType: DtlsContentType.handshake,
      version: 0xFEFD,
      epoch: 0,
      sequenceNumber: 0,
      fragment: handshakeFragment,
    ).encode();
  }

  test('DtlsStateMachine(server) auto-delegates to DTLS 1.3 on v1.3 ClientHello',
      () {
    final cert = EcdsaCertificate.selfSigned();
    final dtls = DtlsStateMachine(role: DtlsRole.server, localCert: cert);

    Uint8List? srtpKeyMaterial;
    dtls.onConnected = (km) => srtpKeyMaterial = km;

    // Build a ClientHello that advertises DTLS 1.3 + secp256r1 + use_srtp.
    final clientKp = EcdhKeyPair.generate();
    final clientRandom = Csprng.randomBytes(32);
    final chBody = buildClientHelloBody(
      random: clientRandom,
      cipherSuites: const [0x1301],
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
          singleEntryKeyShare(
            namedGroup: TlsV13NamedGroup.secp256r1,
            keyExchange: clientKp.publicKeyBytes,
          ),
        ),
        // Offer one SRTP profile webdartc supports.
        TlsExtension(
          TlsV13ExtensionType.useSrtp,
          // profiles_len(2)=2, profile=0x0001, mki_len(1)=0
          bytes([0x00, 0x02, 0x00, 0x01, 0x00]),
        ),
      ],
    );
    final chFull = wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: 0,
      body: chBody,
    );
    final chPacket = wrapAsPlaintext(chFull);

    // Drive the legacy DtlsStateMachine — it should detect DTLS 1.3 and
    // delegate the rest of the flight to the v13 inner.
    final r1 = dtls.processInput(
      chPacket,
      remoteIp: '127.0.0.1',
      remotePort: 5000,
    );
    expect(r1.isOk, isTrue,
        reason: r1.isErr ? '${r1.error}' : '');
    final flight = r1.value.outputPackets;
    expect(flight.length, equals(5),
        reason: 'expected 5 records (SH + EE + Cert + CV + Fin)');

    // Replay the server flight on the synthetic client side, decrypting
    // each encrypted record using keys derived from CH || SH.
    final shRecord = DtlsRecord.parse(flight[0].data, 0)!;
    final shHs = DtlsHandshakeHeader.parse(shRecord.fragment)!;
    final sh = parseServerHelloBody(shHs.body)!;
    Uint8List? serverPub;
    for (final e in sh.extensions) {
      if (e.type == TlsV13ExtensionType.keyShare) {
        final keLen = (e.data[2] << 8) | e.data[3];
        serverPub = e.data.sublist(4, 4 + keLen);
      }
    }
    expect(serverPub, isNotNull);

    final ecdhe = clientKp.computeSharedSecret(serverPub!);
    final transcript = DtlsV13Transcript()
      ..addDtlsMessage(chFull)
      ..addDtlsMessage(shRecord.fragment);
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

    // Walk the four encrypted records; verify EE actually echoes use_srtp,
    // then add each to the transcript so we can compute the client Finished.
    var sawUseSrtp = false;
    for (var i = 0; i < 4; i++) {
      final dec = DtlsV13RecordCrypto.decrypt(
        record: flight[1 + i].data,
        keys: serverHsKeys,
        epoch: 2,
      );
      expect(dec, isNotNull);
      expect(dec!.contentType, equals(DtlsContentType.handshake));
      final h = DtlsHandshakeHeader.parse(dec.content)!;
      if (h.msgType == TlsV13HandshakeType.encryptedExtensions) {
        final exts = parseEncryptedExtensionsBody(h.body)!;
        for (final e in exts) {
          if (e.type == TlsV13ExtensionType.useSrtp) {
            sawUseSrtp = true;
            // Server-form payload: profiles_len(2) + profile(2) + mki_len(1)
            expect(e.data.length, equals(5));
            final selected = (e.data[2] << 8) | e.data[3];
            expect(selected, equals(0x0001));
          }
        }
      }
      transcript.addDtlsMessage(dec.content);
    }
    expect(sawUseSrtp, isTrue,
        reason: 'EncryptedExtensions must echo use_srtp when the client offered it');

    // Build the client Finished and send it back.
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
    final r2 = dtls.processInput(
      clientFinRecord,
      remoteIp: '127.0.0.1',
      remotePort: 5000,
    );
    expect(r2.isOk, isTrue);

    // The legacy class's getter should now reflect the v1.3 inner's choice.
    expect(dtls.selectedSrtpProfileId, equals(0x0001));
    expect(srtpKeyMaterial, isNotNull);
    expect(srtpKeyMaterial!.length, equals(60));
  });

  test('DTLS 1.2 client rejects tampered ServerKeyExchange signature', () {
    final clientCert = EcdsaCertificate.selfSigned();
    final serverCert = EcdsaCertificate.selfSigned();
    final client = DtlsStateMachine(
        role: DtlsRole.client, localCert: clientCert);
    final server = DtlsStateMachine(
        role: DtlsRole.server, localCert: serverCert);
    client.expectedRemoteFingerprint = serverCert.sha256Fingerprint;
    server.expectedRemoteFingerprint = clientCert.sha256Fingerprint;

    // ── ClientHello (no cookie) → server sends HelloVerifyRequest ─────────
    final r0 = client.startHandshake(remoteIp: '10.0.0.2', remotePort: 5001);
    expect(r0.isOk, isTrue);
    final r1 = server.processInput(
      r0.value.outputPackets[0].data,
      remoteIp: '10.0.0.1',
      remotePort: 5000,
    );
    expect(r1.isOk, isTrue);
    expect(r1.value.outputPackets.length, equals(1));
    // ── Client receives HVR → sends ClientHello with cookie ───────────────
    final r2 = client.processInput(
      r1.value.outputPackets[0].data,
      remoteIp: '10.0.0.2',
      remotePort: 5001,
    );
    expect(r2.isOk, isTrue);
    final r3 = server.processInput(
      r2.value.outputPackets[0].data,
      remoteIp: '10.0.0.1',
      remotePort: 5000,
    );
    expect(r3.isOk, isTrue);
    final flight = r3.value.outputPackets;
    expect(flight.length, equals(4),
        reason: 'expected SH + Cert + SKE + SHD');

    // ── Tamper the SKE signature: flip the LAST byte of the record body ───
    // Record layout: 13-byte record header + handshake fragment. The last
    // byte of the SKE record body is the last byte of the ECDSA signature.
    final skeRecordBytes = Uint8List.fromList(flight[2].data);
    skeRecordBytes[skeRecordBytes.length - 1] ^= 0x01;

    // ── Feed records to client in order; expect SKE to fail verification ──
    expect(
        client.processInput(flight[0].data,
            remoteIp: '10.0.0.2', remotePort: 5001).isOk,
        isTrue);
    expect(
        client.processInput(flight[1].data,
            remoteIp: '10.0.0.2', remotePort: 5001).isOk,
        isTrue);
    final rSke = client.processInput(
      skeRecordBytes,
      remoteIp: '10.0.0.2',
      remotePort: 5001,
    );
    expect(rSke.isErr, isTrue,
        reason: 'client must reject a forged ServerKeyExchange signature');
    expect(rSke.error, isA<CryptoError>());
    expect(
      (rSke.error as CryptoError).message,
      equals('DTLS 1.2: ServerKeyExchange signature verification failed'),
    );
  });

  test('DtlsStateMachine(server) keeps DTLS 1.2 path when v1.3 not offered',
      () {
    // Sanity check: a v1.2-only ClientHello (no supported_versions) should
    // continue to be handled by the legacy 1.2 server flow, not the v1.3
    // delegate. We just verify the v1.3 path was NOT taken by checking
    // that the response is a HelloVerifyRequest (1.2 cookie exchange).
    final cert = EcdsaCertificate.selfSigned();
    final dtls = DtlsStateMachine(role: DtlsRole.server, localCert: cert);

    final chBody = buildClientHelloBody(
      random: Uint8List(32),
      cipherSuites: const [0xC02B], // ECDHE_ECDSA_AES128_GCM_SHA256 (v1.2)
      extensions: const [],
    );
    final chFull = wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: 0,
      body: chBody,
    );
    final chPacket = wrapAsPlaintext(chFull);
    final r = dtls.processInput(chPacket,
        remoteIp: '127.0.0.1', remotePort: 5000);
    expect(r.isOk, isTrue);
    // Single output: HelloVerifyRequest at epoch 0.
    expect(r.value.outputPackets.length, equals(1));
    final rec = DtlsRecord.parse(r.value.outputPackets[0].data, 0)!;
    expect(rec.epoch, equals(0));
    expect(rec.contentType, equals(DtlsContentType.handshake));
    final hs = DtlsHandshakeHeader.parse(rec.fragment)!;
    expect(hs.msgType, equals(3)); // HelloVerifyRequest
  });
}
