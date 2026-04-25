import 'dart:typed_data';

import '../../core/state_machine.dart' as core;
import '../../core/types.dart';
import '../../crypto/csprng.dart';
import '../../crypto/ecdh.dart';
import '../../crypto/ecdsa.dart';
import '../../crypto/hmac_sha256.dart';
import '../record.dart';
import 'cipher_suite.dart';
import 'handshake.dart';
import 'key_schedule.dart';
import 'record_crypto.dart';
import 'srtp_export.dart';
import 'transcript.dart';

/// DTLS 1.3 server state machine state (Phase 1 minimum).
enum DtlsV13ServerState {
  /// Listening for an initial ClientHello on epoch 0.
  initial,

  /// Server flight (ServerHello + EncryptedExtensions + Certificate +
  /// CertificateVerify + Finished) has been emitted; awaiting the client's
  /// encrypted Finished on epoch 2.
  waitClientFinished,

  /// Handshake complete. Application data flows on epoch 3.
  connected,

  /// A protocol error has terminated the session.
  failed,
}

/// Pure DTLS 1.3 *server* state machine (RFC 9147 + RFC 8446).
///
/// Phase 1 scope:
///   * server role only (no client / no HelloRetryRequest)
///   * cipher suite `TLS_AES_128_GCM_SHA256` (0x1301) only
///   * ECDHE on `secp256r1` only, ECDSA-P256 server signature
///   * no PSK, 0-RTT, KeyUpdate, ACK, post-handshake auth, or fragmentation
///
/// The handshake flight is emitted as a single [ProcessResult]:
///
///   1. ServerHello                         (epoch 0, plaintext)
///   2. EncryptedExtensions                 (epoch 2, AEAD)
///   3. Certificate                         (epoch 2, AEAD)
///   4. CertificateVerify                   (epoch 2, AEAD)
///   5. server Finished                     (epoch 2, AEAD)
///
/// Each record is its own UDP datagram — fragmentation and packet packing
/// are caller responsibilities for now.
final class DtlsV13ServerStateMachine implements core.ProtocolStateMachine {
  /// Server-side X.509 certificate + signing key. The certificate's DER
  /// bytes are sent in the Certificate message; its private key signs the
  /// CertificateVerify content.
  final EcdsaCertificate localCert;

  // ─── Public state observables ────────────────────────────────────────

  DtlsV13ServerState get state => _state;

  /// The cipher suite negotiated from ClientHello, or null until then.
  TlsV13CipherSuite? get cipherSuite => _suite;

  /// Server's 32-byte ServerHello.random — generated at construction time.
  Uint8List get serverRandom => _serverRandom;

  /// Client's ClientHello.random, available after the first ClientHello.
  Uint8List? get clientRandom => _clientRandom;

  /// `exporter_master_secret` available after handshake completes
  /// (RFC 8446 §7.5). Phase 1 7-3 will plumb this into SRTP key export.
  Uint8List? get exporterMasterSecret => _exporterMasterSecret;

  // ─── Callbacks ────────────────────────────────────────────────────────

  /// Fired exactly once when the handshake transitions to CONNECTED.
  /// The argument is the 60-byte SRTP keying material exported from
  /// `exporter_master_secret` per RFC 5764 §4.2 (laid out as
  /// `client_master_key(16) || server_master_key(16) ||
  /// client_master_salt(14) || server_master_salt(14)`).
  void Function(Uint8List srtpKeyingMaterial)? onConnected;

  /// Fired for every successfully decrypted application_data record.
  void Function(Uint8List data)? onApplicationData;

  // ─── Internal state ───────────────────────────────────────────────────

  DtlsV13ServerState _state = DtlsV13ServerState.initial;

  String? _remoteIp;
  int? _remotePort;

  TlsV13CipherSuite? _suite;
  Uint8List? _clientRandom;
  final Uint8List _serverRandom = Csprng.randomBytes(32);
  Uint8List _legacySessionIdEcho = Uint8List(0);
  EcdhKeyPair? _ecdhKeyPair;
  Uint8List? _peerKeyShare;

  final DtlsV13Transcript _transcript = DtlsV13Transcript();

  Uint8List? _earlySecret;
  Uint8List? _handshakeSecret;
  Uint8List? _masterSecret;
  TrafficKeys? _serverHsKeys;
  TrafficKeys? _clientHsKeys;
  TrafficKeys? _serverApKeys;
  TrafficKeys? _clientApKeys;
  Uint8List? _exporterMasterSecret;

  int _sendSeqEpoch0 = 0;
  int _sendSeqEpoch2 = 0;
  int _sendSeqEpoch3 = 0;
  int _outboundMsgSeq = 0;

  /// The most recently emitted server flight, kept so we can re-send it on
  /// receipt of a duplicate ClientHello (RFC 6347-style retransmit).
  List<OutputPacket>? _lastServerFlight;

  DtlsV13ServerStateMachine({required this.localCert});

  // ─── ProtocolStateMachine ─────────────────────────────────────────────

  @override
  core.Result<ProcessResult, core.ProtocolError> processInput(
    Uint8List packet, {
    required String remoteIp,
    required int remotePort,
  }) {
    _remoteIp = remoteIp;
    _remotePort = remotePort;
    if (packet.isEmpty) return const core.Ok(ProcessResult.empty);

    // Top three bits `001` mark a DTLS 1.3 ciphertext (unified header).
    // Anything else is treated as a legacy DTLSPlaintext record (used for
    // epoch 0 ClientHello / ServerHello).
    if ((packet[0] & 0xE0) == 0x20) {
      return _processCiphertextRecord(packet);
    }
    return _processPlaintextRecord(packet);
  }

  @override
  core.Result<ProcessResult, core.ProtocolError> handleTimeout(
    TimerToken token,
  ) {
    // Phase 1: no automatic retransmission timer. Duplicate ClientHellos
    // trigger flight re-send via [_processPlaintextRecord].
    return const core.Ok(ProcessResult.empty);
  }

  // ─── Record dispatch ──────────────────────────────────────────────────

  core.Result<ProcessResult, core.ProtocolError> _processPlaintextRecord(
    Uint8List packet,
  ) {
    final rec = DtlsRecord.parse(packet, 0);
    if (rec == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad plaintext record'));
    }
    if (rec.epoch != 0) {
      // Encrypted records must come through the unified-header path.
      return const core.Ok(ProcessResult.empty);
    }
    if (rec.contentType != DtlsContentType.handshake) {
      return const core.Ok(ProcessResult.empty);
    }
    return _processHandshakeFragment(rec.fragment);
  }

  core.Result<ProcessResult, core.ProtocolError> _processCiphertextRecord(
    Uint8List packet,
  ) {
    final keys = _state == DtlsV13ServerState.waitClientFinished
        ? _clientHsKeys
        : _clientApKeys;
    if (keys == null) return const core.Ok(ProcessResult.empty);

    final epoch = _state == DtlsV13ServerState.waitClientFinished ? 2 : 3;
    final out = DtlsV13RecordCrypto.decrypt(
      record: packet,
      keys: keys,
      epoch: epoch,
    );
    if (out == null) {
      // RFC 9147 §4.5.3: silently drop unauthenticatable records.
      return const core.Ok(ProcessResult.empty);
    }
    switch (out.contentType) {
      case DtlsContentType.handshake:
        return _processHandshakeFragment(out.content);
      case DtlsContentType.applicationData:
        if (_state == DtlsV13ServerState.connected) {
          onApplicationData?.call(out.content);
        }
        return const core.Ok(ProcessResult.empty);
      case DtlsContentType.alert:
        _state = DtlsV13ServerState.failed;
        return const core.Ok(ProcessResult.empty);
      default:
        return const core.Ok(ProcessResult.empty);
    }
  }

  // ─── Handshake message dispatch ───────────────────────────────────────

  core.Result<ProcessResult, core.ProtocolError> _processHandshakeFragment(
    Uint8List fragment,
  ) {
    final hs = DtlsHandshakeHeader.parse(fragment);
    if (hs == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad handshake header'));
    }
    if (hs.fragmentOffset != 0 || hs.fragmentLength != hs.length) {
      // Phase 1 doesn't reassemble fragmented handshake messages.
      return core.Err(
        const core.ParseError('DTLS 1.3: fragmented handshake unsupported'),
      );
    }
    // The DTLS-form bytes that go into the (1.3-style) transcript hash.
    final fullDtls = fragment.sublist(0, 12 + hs.body.length);

    switch (hs.msgType) {
      case TlsV13HandshakeType.clientHello:
        if (_state == DtlsV13ServerState.initial) {
          return _handleInitialClientHello(hs.body, fullDtls);
        }
        if (_state == DtlsV13ServerState.waitClientFinished &&
            _lastServerFlight != null) {
          // Client retransmitted: re-send our flight verbatim.
          return core.Ok(
            ProcessResult(outputPackets: List.of(_lastServerFlight!)),
          );
        }
        return const core.Ok(ProcessResult.empty);

      case TlsV13HandshakeType.finished:
        if (_state != DtlsV13ServerState.waitClientFinished) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleClientFinished(hs.body, fullDtls);

      default:
        return const core.Ok(ProcessResult.empty);
    }
  }

  // ─── ClientHello → server flight ──────────────────────────────────────

  core.Result<ProcessResult, core.ProtocolError> _handleInitialClientHello(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    final ch = parseClientHello(body);
    if (ch == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad ClientHello'));
    }

    // The client must include supported_versions advertising DTLS 1.3.
    final sv = ch.extensionByType(TlsV13ExtensionType.supportedVersions);
    if (sv == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: ClientHello missing supported_versions'),
      );
    }
    final versions = parseClientHelloSupportedVersionsExtData(sv.data);
    if (versions == null || !versions.contains(dtls13Version)) {
      return core.Err(
        const core.ParseError('DTLS 1.3: client does not offer DTLS 1.3'),
      );
    }

    // Pick a cipher suite from the offer.
    final suite = TlsV13CipherSuite.selectFromOffer(ch.cipherSuites);
    if (suite == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: no overlapping cipher suite'),
      );
    }

    // Pick a key share — we only support secp256r1.
    final ks = ch.extensionByType(TlsV13ExtensionType.keyShare);
    if (ks == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: ClientHello missing key_share'),
      );
    }
    final shares = parseClientHelloKeyShareExtData(ks.data);
    if (shares == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad key_share data'));
    }
    KeyShareEntry? selectedShare;
    for (final s in shares) {
      if (s.group == TlsV13NamedGroup.secp256r1 &&
          s.keyExchange.length == 65 &&
          s.keyExchange[0] == 0x04) {
        selectedShare = s;
        break;
      }
    }
    if (selectedShare == null) {
      // Phase 1 cannot send a HelloRetryRequest; bail out.
      return core.Err(
        const core.ParseError('DTLS 1.3: no secp256r1 key_share offered'),
      );
    }

    // Latch negotiation results.
    _suite = suite;
    _clientRandom = ch.random;
    _legacySessionIdEcho = ch.legacySessionId;
    _peerKeyShare = selectedShare.keyExchange;
    _ecdhKeyPair = EcdhKeyPair.generate();

    _transcript.addDtlsMessage(fullDtls);

    return _sendServerFlight();
  }

  core.Result<ProcessResult, core.ProtocolError> _sendServerFlight() {
    final suite = _suite!;
    final outputs = <OutputPacket>[];

    // ── ServerHello (plaintext, epoch 0) ────────────────────────────────
    final shExts = <TlsExtension>[
      TlsExtension(
        TlsV13ExtensionType.supportedVersions,
        buildServerHelloSupportedVersionsExtData(dtls13Version),
      ),
      TlsExtension(
        TlsV13ExtensionType.keyShare,
        buildServerHelloKeyShareExtData(
          namedGroup: TlsV13NamedGroup.secp256r1,
          keyExchange: _ecdhKeyPair!.publicKeyBytes,
        ),
      ),
    ];
    final shBody = buildServerHelloBody(
      random: _serverRandom,
      legacySessionIdEcho: _legacySessionIdEcho,
      cipherSuite: suite.id,
      extensions: shExts,
    );
    final shFull = wrapHandshake(
      msgType: TlsV13HandshakeType.serverHello,
      msgSeq: _outboundMsgSeq++,
      body: shBody,
    );
    _transcript.addDtlsMessage(shFull);
    outputs.add(_emitPlaintextHandshake(shFull));

    // ── Derive handshake_secret + handshake traffic keys ───────────────
    _earlySecret = TlsV13KeySchedule.computeEarlySecret();
    final ecdheShared =
        _ecdhKeyPair!.computeSharedSecret(_peerKeyShare!);
    _handshakeSecret = TlsV13KeySchedule.computeHandshakeSecret(
      earlySecret: _earlySecret!,
      ecdheSharedSecret: ecdheShared,
    );
    final chShHash = _transcript.hash;
    final cHsTraffic = TlsV13KeySchedule.computeClientHandshakeTrafficSecret(
      handshakeSecret: _handshakeSecret!,
      chShTranscriptHash: chShHash,
    );
    final sHsTraffic = TlsV13KeySchedule.computeServerHandshakeTrafficSecret(
      handshakeSecret: _handshakeSecret!,
      chShTranscriptHash: chShHash,
    );
    _clientHsKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: cHsTraffic,
      keyLength: suite.keyLength,
    );
    _serverHsKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: sHsTraffic,
      keyLength: suite.keyLength,
    );

    // ── EncryptedExtensions, Certificate, CertificateVerify (epoch 2) ──
    _emitEncryptedHandshake(
      type: TlsV13HandshakeType.encryptedExtensions,
      body: buildEncryptedExtensionsBody(const []),
      outputs: outputs,
    );
    _emitEncryptedHandshake(
      type: TlsV13HandshakeType.certificate,
      body: buildCertificateBody(
        certificateRequestContext: Uint8List(0),
        certDerChain: [localCert.derBytes],
      ),
      outputs: outputs,
    );

    final cvSignedContent = certificateVerifySignedContent(
      transcriptHash: _transcript.hash,
      isServer: true,
    );
    final cvSignature = localCert.sign(cvSignedContent);
    _emitEncryptedHandshake(
      type: TlsV13HandshakeType.certificateVerify,
      body: buildCertificateVerifyBody(
        signatureScheme: TlsV13SignatureScheme.ecdsaSecp256r1Sha256,
        signature: cvSignature,
      ),
      outputs: outputs,
    );

    // ── server Finished ────────────────────────────────────────────────
    final serverFinishedVerifyData =
        HmacSha256.compute(_serverHsKeys!.finishedKey, _transcript.hash);
    _emitEncryptedHandshake(
      type: TlsV13HandshakeType.finished,
      body: buildFinishedBody(serverFinishedVerifyData),
      outputs: outputs,
    );

    // ── master_secret + application traffic secrets ────────────────────
    _masterSecret = TlsV13KeySchedule.computeMasterSecret(
      handshakeSecret: _handshakeSecret!,
    );
    final chSfHash = _transcript.hash;
    final cAp = TlsV13KeySchedule.computeClientApplicationTrafficSecret(
      masterSecret: _masterSecret!,
      chServerFinishedTranscriptHash: chSfHash,
    );
    final sAp = TlsV13KeySchedule.computeServerApplicationTrafficSecret(
      masterSecret: _masterSecret!,
      chServerFinishedTranscriptHash: chSfHash,
    );
    _clientApKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: cAp,
      keyLength: suite.keyLength,
    );
    _serverApKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: sAp,
      keyLength: suite.keyLength,
    );
    _exporterMasterSecret = TlsV13KeySchedule.computeExporterMasterSecret(
      masterSecret: _masterSecret!,
      chServerFinishedTranscriptHash: chSfHash,
    );

    _state = DtlsV13ServerState.waitClientFinished;
    _lastServerFlight = List.of(outputs);
    return core.Ok(ProcessResult(outputPackets: outputs));
  }

  // ─── client Finished → CONNECTED ──────────────────────────────────────

  core.Result<ProcessResult, core.ProtocolError> _handleClientFinished(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    final keys = _clientHsKeys;
    if (keys == null) {
      return core.Err(
        const core.StateError('DTLS 1.3: client Finished before keys'),
      );
    }
    // The client computes verify_data over CH..server-Finished, which is
    // exactly what the transcript currently holds.
    final expected = HmacSha256.compute(keys.finishedKey, _transcript.hash);
    if (body.length != expected.length) {
      return core.Err(
        const core.CryptoError('DTLS 1.3: client Finished wrong length'),
      );
    }
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ body[i];
    }
    if (diff != 0) {
      return core.Err(
        const core.CryptoError('DTLS 1.3: client Finished verify_data mismatch'),
      );
    }

    _transcript.addDtlsMessage(fullDtls);
    _state = DtlsV13ServerState.connected;
    final cb = onConnected;
    if (cb != null) {
      cb(DtlsV13SrtpExport.export(
        exporterMasterSecret: _exporterMasterSecret!,
      ));
    }
    return const core.Ok(ProcessResult.empty);
  }

  // ─── Public application-data API ──────────────────────────────────────

  /// Encrypt [data] as an application_data record. Returns an Err if the
  /// handshake hasn't reached CONNECTED yet — callers can still use a
  /// uniform success / failure flow.
  core.Result<ProcessResult, core.ProtocolError> sendApplicationData(
    Uint8List data,
  ) {
    if (_state != DtlsV13ServerState.connected) {
      return core.Err(
        const core.StateError('DTLS 1.3: sendApplicationData before CONNECTED'),
      );
    }
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.applicationData,
      content: data,
      epoch: 3,
      seqNum: _sendSeqEpoch3++,
      keys: _serverApKeys!,
    );
    return core.Ok(
      ProcessResult(
        outputPackets: [
          OutputPacket(
            data: rec,
            remoteIp: _remoteIp!,
            remotePort: _remotePort!,
          ),
        ],
      ),
    );
  }

  // ─── Internal record-emission helpers ─────────────────────────────────

  /// Wrap a handshake fragment in a DTLSPlaintext (epoch 0) record.
  OutputPacket _emitPlaintextHandshake(Uint8List handshakeFragment) {
    final rec = DtlsRecord(
      contentType: DtlsContentType.handshake,
      version: 0xFEFD,
      epoch: 0,
      sequenceNumber: _sendSeqEpoch0++,
      fragment: handshakeFragment,
    ).encode();
    return OutputPacket(
      data: rec,
      remoteIp: _remoteIp!,
      remotePort: _remotePort!,
    );
  }

  /// Build a handshake message of [type] with [body], wrap it in the DTLS
  /// handshake header, add the resulting bytes to the transcript, and
  /// emit them as an encrypted (epoch 2) record.
  void _emitEncryptedHandshake({
    required int type,
    required Uint8List body,
    required List<OutputPacket> outputs,
  }) {
    final fragment = wrapHandshake(
      msgType: type,
      msgSeq: _outboundMsgSeq++,
      body: body,
    );
    _transcript.addDtlsMessage(fragment);
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.handshake,
      content: fragment,
      epoch: 2,
      seqNum: _sendSeqEpoch2++,
      keys: _serverHsKeys!,
    );
    outputs.add(OutputPacket(
      data: rec,
      remoteIp: _remoteIp!,
      remotePort: _remotePort!,
    ));
  }
}

