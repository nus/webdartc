import 'dart:typed_data';

import '../../core/state_machine.dart' as core;
import '../../core/types.dart';
import '../../crypto/csprng.dart';
import '../../crypto/ecdh.dart';
import '../../crypto/ecdsa.dart';
import '../../crypto/hmac_sha256.dart';
import '../../crypto/sha256.dart';
import '../../crypto/x25519.dart';
import '../../crypto/x509_der.dart';
import '../record.dart';
import 'cipher_suite.dart';
import 'handshake.dart';
import 'key_schedule.dart';
import 'record_crypto.dart';
import 'srtp_export.dart';
import 'transcript.dart';

/// DTLS 1.3 client state machine state.
enum DtlsV13ClientState {
  /// Constructed, no ClientHello sent yet.
  initial,

  /// CH1 was emitted on epoch 0; awaiting ServerHello (or HRR).
  sentClientHello,

  /// HRR was received and CH2 emitted on epoch 0; awaiting the real
  /// ServerHello.
  sentSecondClientHello,

  /// ServerHello has been processed and handshake keys derived; awaiting
  /// the encrypted server flight starting with EncryptedExtensions.
  waitEncryptedExtensions,

  /// EncryptedExtensions seen; awaiting Certificate.
  waitCertificate,

  /// Certificate seen; awaiting CertificateVerify.
  waitCertificateVerify,

  /// CertificateVerify seen; awaiting the server's Finished.
  waitServerFinished,

  /// Handshake complete. Application data flows on epoch 3.
  connected,

  /// A protocol error has terminated the session.
  failed,
}

/// Pure DTLS 1.3 *client* state machine (RFC 9147 + RFC 8446).
///
/// Phase 1 scope mirrors the server's:
///   * client role only (no resumption / 0-RTT / KeyUpdate / post-handshake auth)
///   * cipher suite `TLS_AES_128_GCM_SHA256` (0x1301) only
///   * ECDHE on `secp256r1` and `x25519`; both are offered in CH1
///   * ECDSA P-256 / SHA-256 server signature
///   * fragmentation-reassembly is supported for the encrypted flight
///   * server CertificateVerify is verified with [EcdsaVerify].
final class DtlsV13ClientStateMachine implements core.ProtocolStateMachine {
  /// Client-side X.509 certificate + signing key. The DER bytes are sent
  /// in a Certificate message, and the private key signs the
  /// CertificateVerify content, when the server requests client
  /// authentication via CertificateRequest (RFC 8446 §4.3.2).
  final EcdsaCertificate localCert;

  /// Expected SHA-256 fingerprint of the *server's* certificate, formatted
  /// as colon-separated uppercase hex (matching the SDP `a=fingerprint`
  /// convention used by [EcdsaCertificate.sha256Fingerprint]). When
  /// non-null, the client compares this to the server's actual cert
  /// fingerprint after parsing the server Certificate; mismatch fails the
  /// handshake with a `CryptoError`.
  String? expectedRemoteFingerprint;

  // ─── Public state observables ────────────────────────────────────────

  DtlsV13ClientState get state => _state;

  TlsV13CipherSuite? get cipherSuite => _suite;

  Uint8List? get exporterMasterSecret => _exporterMasterSecret;

  int? get selectedSrtpProfileId => _selectedSrtpProfile;

  // ─── Callbacks ────────────────────────────────────────────────────────

  /// Fired exactly once when the handshake transitions to CONNECTED. The
  /// argument is the SRTP keying material exported from
  /// `exporter_master_secret`. Length depends on [selectedSrtpProfileId];
  /// when no use_srtp was negotiated the legacy 60-byte AES-CM length is
  /// used (matches the server class).
  void Function(Uint8List srtpKeyingMaterial)? onConnected;

  /// Fired for every successfully decrypted application_data record.
  void Function(Uint8List data)? onApplicationData;

  // ─── Internal state ───────────────────────────────────────────────────

  DtlsV13ClientState _state = DtlsV13ClientState.initial;

  String? _remoteIp;
  int? _remotePort;

  TlsV13CipherSuite? _suite;
  final Uint8List _clientRandom = Csprng.randomBytes(32);
  final Uint8List _legacySessionId = Uint8List(0);

  /// Negotiated key-exchange group, set when ServerHello is processed.
  int? _selectedGroup;

  /// secp256r1 ephemeral private key. Generated on every ClientHello and
  /// kept until ServerHello selects a group; the unused half is discarded.
  EcdhKeyPair? _ecdhKeyPair;

  /// x25519 ephemeral private key. Generated on every ClientHello and
  /// kept until ServerHello selects a group; the unused half is discarded.
  X25519KeyPair? _x25519KeyPair;

  final DtlsV13Transcript _transcript = DtlsV13Transcript();

  /// SRTP profiles offered by the caller via [startHandshake]. When null,
  /// the use_srtp extension is omitted entirely.
  List<int>? _offeredSrtpProfiles;

  /// SRTP profile the server selected in EncryptedExtensions, or null if
  /// no use_srtp was negotiated.
  int? _selectedSrtpProfile;

  /// 65-byte uncompressed P-256 pubkey extracted from the server's
  /// Certificate message. Used to verify CertificateVerify.
  Uint8List? _peerCertPubKey;

  /// True once the server has emitted a CertificateRequest in its
  /// encrypted flight. When true, the client must produce its own
  /// Certificate + CertificateVerify before its Finished
  /// (RFC 8446 §4.3.2 + §4.4.2-3).
  bool _serverRequestedClientAuth = false;

  /// `certificate_request_context` echoed back in the client Certificate
  /// (RFC 8446 §4.3.2). For mid-handshake mTLS this is empty, but we
  /// preserve whatever the server sends so post-handshake auth could
  /// reuse this slot in future.
  Uint8List _certificateRequestContext = Uint8List(0);

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

  /// Record number of the most recently decrypted inbound record,
  /// captured before handshake dispatch so handlers can build an ACK
  /// (RFC 9147 §7.1) referencing it.
  DtlsAckRecordNumber? _lastRxRecordNumber;

  /// Application-data tx epoch for post-handshake KeyUpdate tracking
  /// (RFC 9147 §6.1). Starts at 3, increments by one per outbound
  /// KeyUpdate.
  int _txAppEpoch = 3;

  /// Application-data rx epoch — symmetrical to [_txAppEpoch] for
  /// records arriving from the peer.
  int _rxAppEpoch = 3;

  /// Set when we received a KeyUpdate(update_requested) from the peer
  /// and owe them a reciprocal KeyUpdate before our next
  /// application_data record (RFC 8446 §4.6.3).
  bool _peerRequestedKeyUpdate = false;

  /// Per-message reassembly buffer for inbound fragmented handshake
  /// messages, keyed by `messageSeq` (RFC 9147 §5.5).
  final Map<int, _Reassembly> _fragmentBuffer = <int, _Reassembly>{};

  /// Cipher suites to advertise in ClientHello, in client-preference order.
  /// Defaults to AES-128-GCM first, ChaCha20-Poly1305 second — matching the
  /// implementation's primary suite while still letting the server pick
  /// ChaCha20 when it prefers (RFC 8446 §4.1.2).
  final List<int> offeredCipherSuites;

  DtlsV13ClientStateMachine({
    required this.localCert,
    this.offeredCipherSuites = const <int>[0x1301, 0x1303],
  });

  // ─── Public start API ─────────────────────────────────────────────────

  /// Begin the handshake. Generates the initial ClientHello flight and
  /// transitions to [DtlsV13ClientState.sentClientHello].
  ///
  /// [supportedSrtpProfiles] is the list of RFC 5764 profile IDs to offer
  /// in `use_srtp`. Passing null omits the extension entirely.
  core.Result<ProcessResult, core.ProtocolError> startHandshake({
    required String remoteIp,
    required int remotePort,
    List<int>? supportedSrtpProfiles,
  }) {
    if (_state != DtlsV13ClientState.initial) {
      return core.Err(
        const core.StateError('DTLS 1.3: startHandshake from non-initial state'),
      );
    }
    _remoteIp = remoteIp;
    _remotePort = remotePort;
    _offeredSrtpProfiles = supportedSrtpProfiles;
    _ecdhKeyPair = EcdhKeyPair.generate();
    _x25519KeyPair = X25519KeyPair.generate();

    final chFull = _buildClientHelloFlight(
      includeBothGroups: true,
      cookie: null,
    );
    _transcript.addDtlsMessage(chFull);
    _state = DtlsV13ClientState.sentClientHello;
    return core.Ok(ProcessResult(
      outputPackets: [_emitPlaintextHandshake(chFull)],
    ));
  }

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

    if ((packet[0] & 0xE0) == 0x20) {
      return _processCiphertextRecord(packet);
    }
    return _processPlaintextRecord(packet);
  }

  @override
  core.Result<ProcessResult, core.ProtocolError> handleTimeout(
    TimerToken token,
  ) {
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
      return const core.Ok(ProcessResult.empty);
    }
    if (rec.contentType != DtlsContentType.handshake) {
      return const core.Ok(ProcessResult.empty);
    }
    return _processHandshakeFragments(rec.fragment);
  }

  core.Result<ProcessResult, core.ProtocolError> _processCiphertextRecord(
    Uint8List packet,
  ) {
    final keys = _state == DtlsV13ClientState.connected
        ? _serverApKeys
        : _serverHsKeys;
    if (keys == null) return const core.Ok(ProcessResult.empty);

    final epoch = _state == DtlsV13ClientState.connected ? _rxAppEpoch : 2;
    final out = DtlsV13RecordCrypto.decrypt(
      record: packet,
      keys: keys,
      epoch: epoch,
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
    );
    if (out == null) {
      return const core.Ok(ProcessResult.empty);
    }
    _lastRxRecordNumber = DtlsAckRecordNumber(epoch, out.seqNum);
    switch (out.contentType) {
      case DtlsContentType.handshake:
        return _processHandshakeFragments(out.content);
      case DtlsContentType.ack:
        // RFC 9147 §7: parse and discard. No per-record retransmit
        // queue to clear yet; received ACKs are informational.
        parseAckRecord(out.content);
        return const core.Ok(ProcessResult.empty);
      case DtlsContentType.applicationData:
        if (_state == DtlsV13ClientState.connected) {
          onApplicationData?.call(out.content);
        }
        return const core.Ok(ProcessResult.empty);
      case DtlsContentType.alert:
        _state = DtlsV13ClientState.failed;
        return const core.Ok(ProcessResult.empty);
      default:
        return const core.Ok(ProcessResult.empty);
    }
  }

  // ─── Handshake fragment dispatch ──────────────────────────────────────

  /// Walk a buffer that may carry one or more concatenated DTLS handshake
  /// records — the unified-header ciphertext can pack several handshake
  /// messages, and EncryptedExtensions / Certificate / CertificateVerify /
  /// Finished can also arrive in independent records.
  core.Result<ProcessResult, core.ProtocolError> _processHandshakeFragments(
    Uint8List buf,
  ) {
    final outputs = <OutputPacket>[];
    var offset = 0;
    while (offset < buf.length) {
      if (buf.length - offset < 12) {
        return core.Err(
          const core.ParseError('DTLS 1.3: short handshake header'),
        );
      }
      final fragLen = (buf[offset + 9] << 16) |
          (buf[offset + 10] << 8) |
          buf[offset + 11];
      final total = 12 + fragLen;
      if (offset + total > buf.length) {
        return core.Err(
          const core.ParseError('DTLS 1.3: truncated handshake fragment'),
        );
      }
      final slice = Uint8List.sublistView(buf, offset, offset + total);
      final r = _processOneHandshakeFragment(slice);
      if (r.isErr) return r;
      outputs.addAll(r.value.outputPackets);
      offset += total;
    }
    return core.Ok(ProcessResult(outputPackets: outputs));
  }

  core.Result<ProcessResult, core.ProtocolError> _processOneHandshakeFragment(
    Uint8List fragment,
  ) {
    final hs = DtlsHandshakeHeader.parse(fragment);
    if (hs == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad handshake header'));
    }

    final int msgType;
    final Uint8List body;
    final Uint8List fullDtls;
    if (hs.fragmentOffset == 0 && hs.fragmentLength == hs.length) {
      msgType = hs.msgType;
      body = hs.body;
      fullDtls = Uint8List.sublistView(fragment, 0, 12 + hs.body.length);
    } else {
      final completed = _accumulateFragment(hs);
      if (completed == null) {
        return const core.Ok(ProcessResult.empty);
      }
      msgType = hs.msgType;
      body = completed;
      fullDtls = _buildSingleFragmentView(hs.msgType, hs.messageSeq, completed);
    }

    switch (msgType) {
      case TlsV13HandshakeType.serverHello:
        if (_state == DtlsV13ClientState.sentClientHello ||
            _state == DtlsV13ClientState.sentSecondClientHello) {
          return _handleServerHello(body, fullDtls);
        }
        return const core.Ok(ProcessResult.empty);

      case TlsV13HandshakeType.encryptedExtensions:
        if (_state != DtlsV13ClientState.waitEncryptedExtensions) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleEncryptedExtensions(body, fullDtls);

      case TlsV13HandshakeType.certificateRequest:
        if (_state != DtlsV13ClientState.waitCertificate) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleCertificateRequest(body, fullDtls);

      case TlsV13HandshakeType.certificate:
        if (_state != DtlsV13ClientState.waitCertificate) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleCertificate(body, fullDtls);

      case TlsV13HandshakeType.certificateVerify:
        if (_state != DtlsV13ClientState.waitCertificateVerify) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleCertificateVerify(body, fullDtls);

      case TlsV13HandshakeType.finished:
        if (_state != DtlsV13ClientState.waitServerFinished) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleServerFinished(body, fullDtls);

      case TlsV13HandshakeType.keyUpdate:
        if (_state != DtlsV13ClientState.connected) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleKeyUpdate(body);

      default:
        return const core.Ok(ProcessResult.empty);
    }
  }

  /// Stash a fragment's body in [_fragmentBuffer]. Returns the fully
  /// reassembled body when complete, otherwise null. Behaviour mirrors
  /// the server's `_accumulateFragment`.
  Uint8List? _accumulateFragment(DtlsHandshakeHeader hs) {
    final buf = _fragmentBuffer.putIfAbsent(
      hs.messageSeq,
      () => _Reassembly(hs.length),
    );
    if (buf.totalLength != hs.length) return null;
    final end = hs.fragmentOffset + hs.body.length;
    if (end > buf.totalLength) return null;
    for (var i = 0; i < hs.body.length; i++) {
      if (!buf.received[hs.fragmentOffset + i]) {
        buf.received[hs.fragmentOffset + i] = true;
        buf.bodyOut[hs.fragmentOffset + i] = hs.body[i];
        buf.bytesGot++;
      }
    }
    if (buf.bytesGot < buf.totalLength) return null;
    _fragmentBuffer.remove(hs.messageSeq);
    return Uint8List.fromList(buf.bodyOut);
  }

  Uint8List _buildSingleFragmentView(
    int msgType,
    int messageSeq,
    Uint8List body,
  ) {
    final out = Uint8List(12 + body.length);
    out[0] = msgType;
    out[1] = (body.length >> 16) & 0xFF;
    out[2] = (body.length >>  8) & 0xFF;
    out[3] =  body.length        & 0xFF;
    out[4] = (messageSeq >> 8) & 0xFF;
    out[5] =  messageSeq        & 0xFF;
    out[6] = 0; out[7] = 0; out[8] = 0;
    out[9]  = (body.length >> 16) & 0xFF;
    out[10] = (body.length >>  8) & 0xFF;
    out[11] =  body.length        & 0xFF;
    out.setRange(12, out.length, body);
    return out;
  }

  // ─── ClientHello build ────────────────────────────────────────────────

  /// Build a ClientHello flight (handshake-wrapped, ready for the record
  /// layer). [includeBothGroups] true for CH1; false (with [cookie] set)
  /// for CH2 — we then send only the group [_selectedGroup] selected via
  /// HRR.
  Uint8List _buildClientHelloFlight({
    required bool includeBothGroups,
    Uint8List? cookie,
  }) {
    final exts = <TlsExtension>[
      TlsExtension(
        TlsV13ExtensionType.supportedVersions,
        _buildClientHelloSupportedVersionsExtData(<int>[dtls13Version]),
      ),
      TlsExtension(
        TlsV13ExtensionType.supportedGroups,
        _buildSupportedGroupsExtData(<int>[
          TlsV13NamedGroup.x25519,
          TlsV13NamedGroup.secp256r1,
        ]),
      ),
      TlsExtension(
        TlsV13ExtensionType.signatureAlgorithms,
        _buildSignatureAlgorithmsExtData(<int>[
          TlsV13SignatureScheme.ecdsaSecp256r1Sha256,
        ]),
      ),
      TlsExtension(
        TlsV13ExtensionType.keyShare,
        _buildClientHelloKeyShareExtData(includeBothGroups: includeBothGroups),
      ),
      if (cookie != null)
        TlsExtension(
          TlsV13ExtensionType.cookie,
          buildCookieExtData(cookie),
        ),
      if (_offeredSrtpProfiles != null && _offeredSrtpProfiles!.isNotEmpty)
        TlsExtension(
          TlsV13ExtensionType.useSrtp,
          _buildOfferedUseSrtpExtData(_offeredSrtpProfiles!),
        ),
    ];

    final body = _buildClientHelloBody(
      random: _clientRandom,
      legacySessionId: _legacySessionId,
      cookie: Uint8List(0),
      cipherSuites: offeredCipherSuites,
      extensions: exts,
    );
    return wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: _outboundMsgSeq++,
      body: body,
    );
  }

  /// Build a DTLS-style ClientHello body. The DTLS-only `cookie` field
  /// (RFC 9147 §5.3) sits between `legacy_session_id` and
  /// `cipher_suites`; for DTLS 1.3 it is always empty (the cookie travels
  /// in the cookie *extension* on retry).
  Uint8List _buildClientHelloBody({
    required Uint8List random,
    required Uint8List legacySessionId,
    required Uint8List cookie,
    required List<int> cipherSuites,
    required List<TlsExtension> extensions,
  }) {
    if (random.length != 32) {
      throw ArgumentError('ClientHello.random must be 32 bytes');
    }
    final extBlock = buildTlsExtensionsBlock(extensions);
    final csTotal = cipherSuites.length * 2;
    final out = Uint8List(
      2 + 32 + 1 + legacySessionId.length + 1 + cookie.length +
          2 + csTotal + 1 + 1 + extBlock.length,
    );
    var off = 0;
    out[off++] = (dtls12Version >> 8) & 0xFF;
    out[off++] =  dtls12Version        & 0xFF;
    out.setRange(off, off + 32, random); off += 32;
    out[off++] = legacySessionId.length;
    out.setRange(off, off + legacySessionId.length, legacySessionId);
    off += legacySessionId.length;
    out[off++] = cookie.length;
    out.setRange(off, off + cookie.length, cookie);
    off += cookie.length;
    out[off++] = (csTotal >> 8) & 0xFF;
    out[off++] =  csTotal        & 0xFF;
    for (final s in cipherSuites) {
      out[off++] = (s >> 8) & 0xFF;
      out[off++] =  s        & 0xFF;
    }
    out[off++] = 1; // legacy_compression_methods length
    out[off++] = 0; // null compression
    out.setRange(off, off + extBlock.length, extBlock);
    return out;
  }

  Uint8List _buildClientHelloSupportedVersionsExtData(List<int> versions) {
    final out = Uint8List(1 + 2 * versions.length);
    out[0] = 2 * versions.length;
    for (var i = 0; i < versions.length; i++) {
      out[1 + 2 * i] = (versions[i] >> 8) & 0xFF;
      out[2 + 2 * i] =  versions[i]        & 0xFF;
    }
    return out;
  }

  Uint8List _buildSupportedGroupsExtData(List<int> groups) {
    final total = 2 * groups.length;
    final out = Uint8List(2 + total);
    out[0] = (total >> 8) & 0xFF;
    out[1] =  total        & 0xFF;
    for (var i = 0; i < groups.length; i++) {
      out[2 + 2 * i] = (groups[i] >> 8) & 0xFF;
      out[3 + 2 * i] =  groups[i]        & 0xFF;
    }
    return out;
  }

  Uint8List _buildSignatureAlgorithmsExtData(List<int> schemes) {
    final total = 2 * schemes.length;
    final out = Uint8List(2 + total);
    out[0] = (total >> 8) & 0xFF;
    out[1] =  total        & 0xFF;
    for (var i = 0; i < schemes.length; i++) {
      out[2 + 2 * i] = (schemes[i] >> 8) & 0xFF;
      out[3 + 2 * i] =  schemes[i]        & 0xFF;
    }
    return out;
  }

  /// Build the ClientHello key_share extension data: a 2-byte total length
  /// followed by KeyShareEntry (group(2) || keLen(2) || ke). When
  /// [includeBothGroups] is true (CH1), both x25519 and secp256r1 entries
  /// are sent — most recent browsers emit both because either can be
  /// preferred by the server. When false (CH2 after HRR), only the
  /// [_selectedGroup] entry is sent.
  Uint8List _buildClientHelloKeyShareExtData({required bool includeBothGroups}) {
    final entries = <Uint8List>[];
    if (includeBothGroups) {
      entries.add(buildServerHelloKeyShareExtData(
        namedGroup: TlsV13NamedGroup.x25519,
        keyExchange: _x25519KeyPair!.publicKeyBytes,
      ));
      entries.add(buildServerHelloKeyShareExtData(
        namedGroup: TlsV13NamedGroup.secp256r1,
        keyExchange: _ecdhKeyPair!.publicKeyBytes,
      ));
    } else {
      final g = _selectedGroup!;
      entries.add(buildServerHelloKeyShareExtData(
        namedGroup: g,
        keyExchange: g == TlsV13NamedGroup.x25519
            ? _x25519KeyPair!.publicKeyBytes
            : _ecdhKeyPair!.publicKeyBytes,
      ));
    }
    var listLen = 0;
    for (final e in entries) {
      listLen += e.length;
    }
    final out = Uint8List(2 + listLen);
    out[0] = (listLen >> 8) & 0xFF;
    out[1] =  listLen        & 0xFF;
    var off = 2;
    for (final e in entries) {
      out.setRange(off, off + e.length, e);
      off += e.length;
    }
    return out;
  }

  /// Build a use_srtp extension data block for a ClientHello: an offered
  /// list of profile IDs followed by an empty MKI. Mirrors RFC 5764 §4.1.1.
  Uint8List _buildOfferedUseSrtpExtData(List<int> profiles) {
    final profilesLen = 2 * profiles.length;
    final out = Uint8List(2 + profilesLen + 1);
    out[0] = (profilesLen >> 8) & 0xFF;
    out[1] =  profilesLen        & 0xFF;
    for (var i = 0; i < profiles.length; i++) {
      out[2 + 2 * i] = (profiles[i] >> 8) & 0xFF;
      out[3 + 2 * i] =  profiles[i]        & 0xFF;
    }
    out[2 + profilesLen] = 0;
    return out;
  }

  // ─── ServerHello / HRR ────────────────────────────────────────────────

  core.Result<ProcessResult, core.ProtocolError> _handleServerHello(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    final sh = parseServerHelloBody(body);
    if (sh == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad ServerHello'));
    }
    if (_isHelloRetryRequest(sh.random)) {
      return _handleHelloRetryRequest(sh, fullDtls);
    }

    // Real ServerHello.
    if (_state != DtlsV13ClientState.sentClientHello &&
        _state != DtlsV13ClientState.sentSecondClientHello) {
      return const core.Ok(ProcessResult.empty);
    }

    final suite = TlsV13CipherSuite.byId(sh.cipherSuite);
    if (suite == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: server picked unsupported cipher suite'),
      );
    }
    _suite = suite;

    final svExt = _findExtension(sh.extensions, TlsV13ExtensionType.supportedVersions);
    if (svExt == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: ServerHello missing supported_versions'),
      );
    }
    if (svExt.data.length != 2 ||
        ((svExt.data[0] << 8) | svExt.data[1]) != dtls13Version) {
      return core.Err(
        const core.ParseError('DTLS 1.3: ServerHello supported_versions ≠ DTLS 1.3'),
      );
    }

    final ksExt = _findExtension(sh.extensions, TlsV13ExtensionType.keyShare);
    if (ksExt == null || ksExt.data.length < 4) {
      return core.Err(
        const core.ParseError('DTLS 1.3: ServerHello missing key_share'),
      );
    }
    final group = (ksExt.data[0] << 8) | ksExt.data[1];
    final keLen = (ksExt.data[2] << 8) | ksExt.data[3];
    if (4 + keLen != ksExt.data.length) {
      return core.Err(const core.ParseError('DTLS 1.3: bad ServerHello key_share'));
    }
    final serverPub = ksExt.data.sublist(4, 4 + keLen);

    if (_selectedGroup != null && _selectedGroup != group) {
      // After HRR the server must stick with the requested group.
      return core.Err(
        const core.ParseError('DTLS 1.3: ServerHello group differs from HRR'),
      );
    }
    _selectedGroup = group;

    Uint8List? ecdheShared;
    if (group == TlsV13NamedGroup.x25519) {
      if (serverPub.length != 32) {
        return core.Err(
          const core.ParseError('DTLS 1.3: bad x25519 server key_share length'),
        );
      }
      ecdheShared = _x25519KeyPair!.computeSharedSecret(serverPub);
    } else if (group == TlsV13NamedGroup.secp256r1) {
      if (serverPub.length != 65 || serverPub[0] != 0x04) {
        return core.Err(
          const core.ParseError('DTLS 1.3: bad secp256r1 server key_share'),
        );
      }
      ecdheShared = _ecdhKeyPair!.computeSharedSecret(serverPub);
    } else {
      return core.Err(
        const core.ParseError('DTLS 1.3: server selected unsupported group'),
      );
    }
    if (ecdheShared == null) {
      return core.Err(
        const core.CryptoError('DTLS 1.3: ECDHE produced low-order point'),
      );
    }

    _transcript.addDtlsMessage(fullDtls);

    _earlySecret = TlsV13KeySchedule.computeEarlySecret();
    _handshakeSecret = TlsV13KeySchedule.computeHandshakeSecret(
      earlySecret: _earlySecret!,
      ecdheSharedSecret: ecdheShared,
    );
    final chShHash = _transcript.hash;
    _clientHsKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: TlsV13KeySchedule.computeClientHandshakeTrafficSecret(
        handshakeSecret: _handshakeSecret!,
        chShTranscriptHash: chShHash,
      ),
      keyLength: suite.keyLength,
    );
    _serverHsKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: TlsV13KeySchedule.computeServerHandshakeTrafficSecret(
        handshakeSecret: _handshakeSecret!,
        chShTranscriptHash: chShHash,
      ),
      keyLength: suite.keyLength,
    );

    _state = DtlsV13ClientState.waitEncryptedExtensions;
    return const core.Ok(ProcessResult.empty);
  }

  /// Whether [random] equals the RFC 8446 §4.1.4 HelloRetryRequest sentinel.
  bool _isHelloRetryRequest(Uint8List random) {
    if (random.length != helloRetryRequestRandom.length) return false;
    for (var i = 0; i < random.length; i++) {
      if (random[i] != helloRetryRequestRandom[i]) return false;
    }
    return true;
  }

  core.Result<ProcessResult, core.ProtocolError> _handleHelloRetryRequest(
    ServerHelloMessage hrr,
    Uint8List fullDtls,
  ) {
    if (_state != DtlsV13ClientState.sentClientHello) {
      // Two HRRs in a row are forbidden by RFC 8446 §4.1.4.
      return core.Err(
        const core.ParseError('DTLS 1.3: unexpected second HelloRetryRequest'),
      );
    }
    final suite = TlsV13CipherSuite.byId(hrr.cipherSuite);
    if (suite == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: HRR picked unsupported cipher suite'),
      );
    }
    _suite = suite;

    final ksExt = _findExtension(hrr.extensions, TlsV13ExtensionType.keyShare);
    if (ksExt == null) {
      return core.Err(const core.ParseError('DTLS 1.3: HRR missing key_share'));
    }
    final demanded = parseHrrKeyShareExtData(ksExt.data);
    if (demanded == null) {
      return core.Err(const core.ParseError('DTLS 1.3: HRR bad key_share'));
    }
    if (demanded != TlsV13NamedGroup.x25519 &&
        demanded != TlsV13NamedGroup.secp256r1) {
      return core.Err(
        const core.ParseError('DTLS 1.3: HRR demands unsupported group'),
      );
    }

    final cookieExt = _findExtension(hrr.extensions, TlsV13ExtensionType.cookie);
    if (cookieExt == null) {
      return core.Err(const core.ParseError('DTLS 1.3: HRR missing cookie'));
    }
    final cookie = parseCookieExtData(cookieExt.data);
    if (cookie == null) {
      return core.Err(const core.ParseError('DTLS 1.3: HRR bad cookie'));
    }
    _selectedGroup = demanded;

    // RFC 8446 §4.4.1: replace transcript with synthetic_message_hash(CH1),
    // then append HRR before CH2.
    _transcript.replaceWithSyntheticHash();
    _transcript.addDtlsMessage(fullDtls);

    final ch2Full = _buildClientHelloFlight(
      includeBothGroups: false,
      cookie: cookie,
    );
    _transcript.addDtlsMessage(ch2Full);
    _state = DtlsV13ClientState.sentSecondClientHello;
    return core.Ok(ProcessResult(
      outputPackets: [_emitPlaintextHandshake(ch2Full)],
    ));
  }

  TlsExtension? _findExtension(List<TlsExtension> exts, int type) {
    for (final e in exts) {
      if (e.type == type) return e;
    }
    return null;
  }

  // ─── EncryptedExtensions / Certificate / CertificateVerify ────────────

  core.Result<ProcessResult, core.ProtocolError> _handleEncryptedExtensions(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    final exts = parseEncryptedExtensionsBody(body);
    if (exts == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: bad EncryptedExtensions'),
      );
    }
    final useSrtp = _findExtension(exts, TlsV13ExtensionType.useSrtp);
    if (useSrtp != null) {
      final selected = parseUseSrtpExtData(useSrtp.data);
      if (selected != null && selected.length == 1) {
        _selectedSrtpProfile = selected[0];
      }
    }
    _transcript.addDtlsMessage(fullDtls);
    _state = DtlsV13ClientState.waitCertificate;
    return const core.Ok(ProcessResult.empty);
  }

  core.Result<ProcessResult, core.ProtocolError> _handleCertificateRequest(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    final cr = parseCertificateRequestBody(body);
    if (cr == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: bad CertificateRequest'),
      );
    }
    _serverRequestedClientAuth = true;
    _certificateRequestContext = cr.certificateRequestContext;
    _transcript.addDtlsMessage(fullDtls);
    // Stay in waitCertificate — the server still owes us its own
    // Certificate + CertificateVerify + Finished.
    return const core.Ok(ProcessResult.empty);
  }

  core.Result<ProcessResult, core.ProtocolError> _handleCertificate(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    // We accept the server's certificate without trust-chain validation —
    // WebRTC validates the cert at the application layer through the SDP
    // `a=fingerprint` line, so the DTLS layer's job is only to bind the
    // session to that public key. Just sanity-check the structure.
    if (body.isEmpty) {
      return core.Err(const core.ParseError('DTLS 1.3: empty Certificate'));
    }
    final ctxLen = body[0];
    if (1 + ctxLen + 3 > body.length) {
      return core.Err(const core.ParseError('DTLS 1.3: bad Certificate context'));
    }
    var off = 1 + ctxLen;
    final listLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2];
    off += 3;
    if (off + listLen != body.length || listLen == 0) {
      return core.Err(const core.ParseError('DTLS 1.3: bad Certificate list'));
    }
    // First CertificateEntry: cert_data_len(3) || cert_data || extensions_len(2) || extensions.
    if (off + 3 > body.length) {
      return core.Err(const core.ParseError('DTLS 1.3: bad CertificateEntry'));
    }
    final certLen =
        (body[off] << 16) | (body[off + 1] << 8) | body[off + 2];
    off += 3;
    if (off + certLen > body.length) {
      return core.Err(const core.ParseError('DTLS 1.3: truncated cert_data'));
    }
    final certDer = Uint8List.sublistView(body, off, off + certLen);

    final expected = expectedRemoteFingerprint;
    if (expected != null) {
      final fp = Sha256.hash(certDer)
          .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
          .join(':');
      if (fp != expected) {
        return core.Err(
          const core.CryptoError(
              'DTLS 1.3: server cert fingerprint mismatch'),
        );
      }
    }

    final pub = extractEcdsaP256PublicKey(certDer);
    if (pub == null) {
      return core.Err(
        const core.CryptoError(
            'DTLS 1.3: server cert is not P-256 ecPublicKey'),
      );
    }
    _peerCertPubKey = pub;

    _transcript.addDtlsMessage(fullDtls);
    _state = DtlsV13ClientState.waitCertificateVerify;
    return const core.Ok(ProcessResult.empty);
  }

  core.Result<ProcessResult, core.ProtocolError> _handleCertificateVerify(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    if (body.length < 4) {
      return core.Err(const core.ParseError('DTLS 1.3: short CertificateVerify'));
    }
    final scheme = (body[0] << 8) | body[1];
    final sigLen = (body[2] << 8) | body[3];
    if (4 + sigLen != body.length) {
      return core.Err(const core.ParseError('DTLS 1.3: bad CertificateVerify'));
    }
    if (scheme != TlsV13SignatureScheme.ecdsaSecp256r1Sha256) {
      return core.Err(
        const core.CryptoError(
            'DTLS 1.3: server CertificateVerify scheme not supported'),
      );
    }
    final signature = Uint8List.sublistView(body, 4, 4 + sigLen);

    final peerPub = _peerCertPubKey;
    if (peerPub == null) {
      return core.Err(
        const core.StateError(
            'DTLS 1.3: CertificateVerify before Certificate'),
      );
    }
    final signedContent = certificateVerifySignedContent(
      transcriptHash: _transcript.hash,
      isServer: true,
    );
    final ok = EcdsaVerify.verifyP256Sha256(
      publicKey: peerPub,
      message: signedContent,
      signature: signature,
    );
    if (!ok) {
      return core.Err(
        const core.CryptoError(
            'DTLS 1.3: server CertificateVerify failed'),
      );
    }

    _transcript.addDtlsMessage(fullDtls);
    _state = DtlsV13ClientState.waitServerFinished;
    return const core.Ok(ProcessResult.empty);
  }

  // ─── Server Finished → CONNECTED ──────────────────────────────────────

  core.Result<ProcessResult, core.ProtocolError> _handleServerFinished(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    final keys = _serverHsKeys;
    if (keys == null) {
      return core.Err(
        const core.StateError('DTLS 1.3: server Finished before keys'),
      );
    }
    final expected = HmacSha256.compute(keys.finishedKey, _transcript.hash);
    if (body.length != expected.length) {
      return core.Err(
        const core.CryptoError('DTLS 1.3: server Finished wrong length'),
      );
    }
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ body[i];
    }
    if (diff != 0) {
      return core.Err(
        const core.CryptoError('DTLS 1.3: server Finished verify_data mismatch'),
      );
    }
    _transcript.addDtlsMessage(fullDtls);

    // Derive application traffic secrets *before* sending client Finished —
    // RFC 8446 §7.1 anchors them at CH..server-Finished, not the
    // client-Finished hash.
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
      keyLength: _suite!.keyLength,
    );
    _serverApKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: sAp,
      keyLength: _suite!.keyLength,
    );
    _exporterMasterSecret = TlsV13KeySchedule.computeExporterMasterSecret(
      masterSecret: _masterSecret!,
      chServerFinishedTranscriptHash: chSfHash,
    );

    final outputs = <OutputPacket>[];

    // mTLS: when the server asked for client auth, the client's response
    // flight is `Certificate || CertificateVerify || Finished`. Each of
    // the three messages is folded into the transcript before the next is
    // built, so the CV signs `…serverFinished || clientCert` and the
    // client Finished MAC covers `…clientCert || clientCertificateVerify`.
    if (_serverRequestedClientAuth) {
      final certFragment = wrapHandshake(
        msgType: TlsV13HandshakeType.certificate,
        msgSeq: _outboundMsgSeq++,
        body: buildCertificateBody(
          certificateRequestContext: _certificateRequestContext,
          certDerChain: <Uint8List>[localCert.derBytes],
        ),
      );
      _transcript.addDtlsMessage(certFragment);
      outputs.add(_emitEncryptedHandshakeRecord(certFragment));

      final cvSigned = certificateVerifySignedContent(
        transcriptHash: _transcript.hash,
        isServer: false,
      );
      final cvSignature = localCert.sign(cvSigned);
      final cvFragment = wrapHandshake(
        msgType: TlsV13HandshakeType.certificateVerify,
        msgSeq: _outboundMsgSeq++,
        body: buildCertificateVerifyBody(
          signatureScheme: TlsV13SignatureScheme.ecdsaSecp256r1Sha256,
          signature: cvSignature,
        ),
      );
      _transcript.addDtlsMessage(cvFragment);
      outputs.add(_emitEncryptedHandshakeRecord(cvFragment));
    }

    // Build & send client Finished (epoch 2, encrypted with client_hs).
    final clientVerifyData =
        HmacSha256.compute(_clientHsKeys!.finishedKey, _transcript.hash);
    final finFragment = wrapHandshake(
      msgType: TlsV13HandshakeType.finished,
      msgSeq: _outboundMsgSeq++,
      body: buildFinishedBody(clientVerifyData),
    );
    outputs.add(_emitEncryptedHandshakeRecord(finFragment));

    _state = DtlsV13ClientState.connected;
    final cb = onConnected;
    if (cb != null) {
      final exportLen = _selectedSrtpProfile != null
          ? _srtpExportLengthForProfile(_selectedSrtpProfile!)
          : DtlsV13SrtpExport.srtpAes128CmHmacSha180Length;
      cb(DtlsV13SrtpExport.export(
        exporterMasterSecret: _exporterMasterSecret!,
        length: exportLen,
      ));
    }
    return core.Ok(ProcessResult(outputPackets: outputs));
  }

  // ─── Application data ─────────────────────────────────────────────────

  core.Result<ProcessResult, core.ProtocolError> sendApplicationData(
    Uint8List data,
  ) {
    if (_state != DtlsV13ClientState.connected) {
      return core.Err(
        const core.StateError('DTLS 1.3: sendApplicationData before CONNECTED'),
      );
    }
    final outputs = <OutputPacket>[];
    if (_peerRequestedKeyUpdate) {
      outputs.add(_emitKeyUpdate(KeyUpdateRequest.notRequested));
    }
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.applicationData,
      content: data,
      epoch: _txAppEpoch,
      seqNum: _sendSeqEpoch3++,
      keys: _clientApKeys!,
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
    );
    outputs.add(OutputPacket(
      data: rec,
      remoteIp: _remoteIp!,
      remotePort: _remotePort!,
    ));
    return core.Ok(ProcessResult(outputPackets: outputs));
  }

  /// Trigger a post-handshake `KeyUpdate` (RFC 8446 §4.6.3 / RFC 9147
  /// §6.1). Same shape as [DtlsV13ServerStateMachine.requestKeyUpdate].
  core.Result<ProcessResult, core.ProtocolError> requestKeyUpdate({
    bool requestPeerUpdate = false,
  }) {
    if (_state != DtlsV13ClientState.connected) {
      return core.Err(
        const core.StateError('DTLS 1.3: requestKeyUpdate before CONNECTED'),
      );
    }
    final pkt = _emitKeyUpdate(
      requestPeerUpdate
          ? KeyUpdateRequest.requested
          : KeyUpdateRequest.notRequested,
    );
    return core.Ok(ProcessResult(outputPackets: [pkt]));
  }

  /// Build, encrypt, and emit a KeyUpdate handshake message under the
  /// current tx app keys. The KeyUpdate goes out under the old keys and
  /// then the tx side rotates to the next generation per RFC 9147 §6.1.
  OutputPacket _emitKeyUpdate(int request) {
    final body = buildKeyUpdateBody(request);
    final fragment = wrapHandshake(
      msgType: TlsV13HandshakeType.keyUpdate,
      msgSeq: _outboundMsgSeq++,
      body: body,
    );
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.handshake,
      content: fragment,
      epoch: _txAppEpoch,
      seqNum: _sendSeqEpoch3++,
      keys: _clientApKeys!,
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
    );
    final nextSecret = TlsV13KeySchedule.deriveNextTrafficSecret(
      _clientApKeys!.trafficSecret,
    );
    _clientApKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: nextSecret,
      keyLength: (_suite ?? TlsV13CipherSuite.aes128GcmSha256).keyLength,
    );
    _txAppEpoch += 1;
    _sendSeqEpoch3 = 0;
    _peerRequestedKeyUpdate = false;
    return OutputPacket(
      data: rec,
      remoteIp: _remoteIp!,
      remotePort: _remotePort!,
    );
  }

  /// Handle peer KeyUpdate: rotate rx keys to next gen, bump rx epoch,
  /// emit an ACK of the KeyUpdate record (RFC 9147 §7), and optionally
  /// schedule reciprocal KeyUpdate.
  core.Result<ProcessResult, core.ProtocolError> _handleKeyUpdate(
    Uint8List body,
  ) {
    final req = parseKeyUpdateBody(body);
    if (req == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: malformed KeyUpdate body'),
      );
    }
    final ackRn = _lastRxRecordNumber!;
    final nextSecret = TlsV13KeySchedule.deriveNextTrafficSecret(
      _serverApKeys!.trafficSecret,
    );
    _serverApKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: nextSecret,
      keyLength: (_suite ?? TlsV13CipherSuite.aes128GcmSha256).keyLength,
    );
    _rxAppEpoch += 1;
    if (req == KeyUpdateRequest.requested) {
      _peerRequestedKeyUpdate = true;
    }
    final ackPkt = _emitAck([ackRn]);
    return core.Ok(ProcessResult(outputPackets: [ackPkt]));
  }

  /// Encrypt + emit an ACK record (RFC 9147 §7) at the current tx app
  /// epoch under the client's app keys.
  OutputPacket _emitAck(List<DtlsAckRecordNumber> records) {
    final body = buildAckRecord(records);
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.ack,
      content: body,
      epoch: _txAppEpoch,
      seqNum: _sendSeqEpoch3++,
      keys: _clientApKeys!,
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
    );
    return OutputPacket(
      data: rec,
      remoteIp: _remoteIp!,
      remotePort: _remotePort!,
    );
  }

  // ─── Helpers ──────────────────────────────────────────────────────────

  /// Bytes of TLS-exported keying material the negotiated SRTP profile
  /// expects — mirrors the server class's table.
  static int _srtpExportLengthForProfile(int profileId) {
    switch (profileId) {
      case 0x0001:
      case 0x0002:
        return 60;
      case 0x0007:
        return 56;
      case 0x0008:
        return 88;
      default:
        return 60;
    }
  }

  /// Encrypt [handshakeFragment] under the client's epoch-2 handshake
  /// keys and wrap it in an OutputPacket bound for the current peer.
  OutputPacket _emitEncryptedHandshakeRecord(Uint8List handshakeFragment) {
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.handshake,
      content: handshakeFragment,
      epoch: 2,
      seqNum: _sendSeqEpoch2++,
      keys: _clientHsKeys!,
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
    );
    return OutputPacket(
      data: rec,
      remoteIp: _remoteIp!,
      remotePort: _remotePort!,
    );
  }

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
}

/// Reassembly state for a single in-flight handshake message.
final class _Reassembly {
  final int totalLength;
  final List<int> bodyOut;
  final List<bool> received;
  int bytesGot = 0;

  _Reassembly(this.totalLength)
      : bodyOut = List<int>.filled(totalLength, 0),
        received = List<bool>.filled(totalLength, false);
}
