import 'dart:typed_data';

import '../../core/state_machine.dart' as core;
import '../../core/types.dart';
import '../../crypto/csprng.dart';
import '../../crypto/ecdh.dart';
import '../../crypto/ecdsa.dart';
import '../../crypto/hmac_sha256.dart';
import '../../crypto/x25519.dart';
import '../record.dart';
import 'cipher_suite.dart';
import 'handshake.dart';
import 'key_schedule.dart';
import 'record_crypto.dart';
import 'srtp_export.dart';
import 'transcript.dart';

/// DTLS 1.3 server state machine state.
enum DtlsV13ServerState {
  /// Listening for an initial ClientHello on epoch 0.
  initial,

  /// HelloRetryRequest has been emitted; awaiting the client's
  /// resubmitted (and now key-share-acceptable) ClientHello.
  waitSecondClientHello,

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

  /// SRTP protection profile (RFC 5764) negotiated via the use_srtp extension,
  /// or null when the client did not offer one we recognise. Set during
  /// ClientHello processing; valid from that point forward.
  int? get selectedSrtpProfileId => _selectedSrtpProfile;

  // ─── Callbacks ────────────────────────────────────────────────────────

  /// Fired exactly once when the handshake transitions to CONNECTED.
  /// The argument is the SRTP keying material exported from
  /// `exporter_master_secret` per RFC 5764 §4.2. Its length and layout
  /// depend on the negotiated SRTP profile (see [selectedSrtpProfileId]):
  ///   * SRTP_AES128_CM_HMAC_SHA1_80 / _32 → 60 bytes
  ///     (16+16 master keys, 14+14 master salts).
  ///   * SRTP_AEAD_AES_128_GCM             → 56 bytes
  ///     (16+16 master keys, 12+12 master salts) per RFC 7714 §12.
  ///   * SRTP_AEAD_AES_256_GCM             → 88 bytes
  ///     (32+32 master keys, 12+12 master salts) per RFC 7714 §12.
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

  /// Negotiated key-exchange group for this session — either
  /// `secp256r1` (0x0017) or `x25519` (0x001D). Set during ClientHello
  /// processing and used to pick the right public-key encoding for the
  /// ServerHello key_share and the right scalar-multiplication routine
  /// for the ECDHE shared secret.
  int? _selectedGroup;

  /// secp256r1 ephemeral private key, populated when [_selectedGroup] is
  /// `secp256r1`. Null otherwise.
  EcdhKeyPair? _ecdhKeyPair;

  /// x25519 ephemeral private key, populated when [_selectedGroup] is
  /// `x25519`. Null otherwise.
  X25519KeyPair? _x25519KeyPair;
  Uint8List? _peerKeyShare;

  final DtlsV13Transcript _transcript = DtlsV13Transcript();

  /// Selected SRTP profile from RFC 5764 use_srtp negotiation, e.g. 0x0001
  /// for `SRTP_AES128_CM_HMAC_SHA1_80` or 0x0007 for `SRTP_AEAD_AES_128_GCM`.
  /// `null` until the ClientHello has been parsed.
  int? _selectedSrtpProfile;

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

  /// In-progress handshake message reassembly. Keyed by `messageSeq`. Each
  /// entry buffers the full message body until every fragment has arrived
  /// (RFC 9147 §5.5).
  final Map<int, _Reassembly> _fragmentBuffer = <int, _Reassembly>{};

  /// Cookie sent in the HelloRetryRequest. The client must echo it
  /// verbatim in its second ClientHello (RFC 8446 §4.2.2). Null when no
  /// HRR has been emitted.
  Uint8List? _hrrCookie;

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

    // Reassemble fragmented handshake messages (RFC 9147 §5.5). When a
    // record carries the entire message in one fragment we use its bytes
    // directly; otherwise we accumulate fragments by messageSeq until the
    // whole body is in hand, then synthesize a single-fragment view.
    final int msgType;
    final Uint8List body;
    final Uint8List fullDtls;
    if (hs.fragmentOffset == 0 && hs.fragmentLength == hs.length) {
      msgType = hs.msgType;
      body = hs.body;
      fullDtls = fragment.sublist(0, 12 + hs.body.length);
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
      case TlsV13HandshakeType.clientHello:
        if (_state == DtlsV13ServerState.initial) {
          return _handleInitialClientHello(body, fullDtls);
        }
        if (_state == DtlsV13ServerState.waitSecondClientHello) {
          return _handleSecondClientHello(body, fullDtls);
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
        return _handleClientFinished(body, fullDtls);

      default:
        return const core.Ok(ProcessResult.empty);
    }
  }

  /// Stash a fragment's body in [_fragmentBuffer]. Returns the fully
  /// reassembled body once every byte has been observed, otherwise null.
  /// Out-of-order arrival, duplicate fragments, and overlapping fragments
  /// are tolerated; the latest copy of a given byte wins.
  Uint8List? _accumulateFragment(DtlsHandshakeHeader hs) {
    final buf = _fragmentBuffer.putIfAbsent(
      hs.messageSeq,
      () => _Reassembly(hs.length),
    );
    if (buf.totalLength != hs.length) {
      // Inconsistent total length across fragments — can't reassemble.
      return null;
    }
    final end = hs.fragmentOffset + hs.body.length;
    if (end > buf.totalLength) return null;
    for (var i = 0; i < hs.body.length; i++) {
      if (!buf.received[hs.fragmentOffset + i]) {
        buf.received[hs.fragmentOffset + i] = true;
        buf.bodyOut[hs.fragmentOffset + i] = hs.body[i];
        buf.bytesGot++;
      } else {
        // Already received this byte; keep the existing copy.
      }
    }
    if (buf.bytesGot < buf.totalLength) return null;
    _fragmentBuffer.remove(hs.messageSeq);
    return Uint8List.fromList(buf.bodyOut);
  }

  /// Build the DTLS-form bytes a fully-reassembled handshake message would
  /// have if it had been sent as a single fragment — `type(1) + length(3)
  /// + msg_seq(2) + frag_offset=0(3) + frag_length=length(3) + body`. This
  /// is what the transcript hash and downstream handlers expect.
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
    // We accept either x25519 (preferred, since most WebRTC clients only
    // key_share that group) or secp256r1, in client-offered order.
    KeyShareEntry? selectedShare;
    int? selectedGroup;
    for (final s in shares) {
      if (s.group == TlsV13NamedGroup.x25519 && s.keyExchange.length == 32) {
        selectedShare = s;
        selectedGroup = TlsV13NamedGroup.x25519;
        break;
      }
      if (s.group == TlsV13NamedGroup.secp256r1 &&
          s.keyExchange.length == 65 &&
          s.keyExchange[0] == 0x04) {
        selectedShare = s;
        selectedGroup = TlsV13NamedGroup.secp256r1;
        break;
      }
    }
    if (selectedShare == null || selectedGroup == null) {
      // No usable key_share. If the client lists a group we support in
      // its `supported_groups`, send a HelloRetryRequest demanding it
      // (RFC 8446 §4.1.4). Otherwise the negotiation is hopeless.
      final hrrGroup = _pickHrrGroup(ch);
      if (hrrGroup == null) {
        return core.Err(
          const core.ParseError(
            'DTLS 1.3: client offers no x25519 / secp256r1 group',
          ),
        );
      }
      return _sendHelloRetryRequest(
        ch: ch,
        fullDtls: fullDtls,
        suite: suite,
        selectedGroup: hrrGroup,
      );
    }

    _negotiateUseSrtp(ch);
    return _completeClientHello(
      random: ch.random,
      legacySessionId: ch.legacySessionId,
      suite: suite,
      selectedGroup: selectedGroup,
      peerKeyShare: selectedShare.keyExchange,
      fullDtls: fullDtls,
    );
  }

  /// Latch negotiation results from a ClientHello and emit the server's
  /// flight. Shared between the no-HRR path (called from
  /// [_handleInitialClientHello]) and the HRR path (called from
  /// [_handleSecondClientHello]) — the former adds the CH directly to the
  /// transcript, the latter has already added HRR + the synthetic
  /// message_hash placeholder when reaching this point.
  core.Result<ProcessResult, core.ProtocolError> _completeClientHello({
    required Uint8List random,
    required Uint8List legacySessionId,
    required TlsV13CipherSuite suite,
    required int selectedGroup,
    required Uint8List peerKeyShare,
    required Uint8List fullDtls,
  }) {
    _suite = suite;
    _clientRandom = random;
    _legacySessionIdEcho = legacySessionId;
    _peerKeyShare = peerKeyShare;
    _selectedGroup = selectedGroup;
    if (selectedGroup == TlsV13NamedGroup.x25519) {
      _x25519KeyPair = X25519KeyPair.generate();
    } else {
      _ecdhKeyPair = EcdhKeyPair.generate();
    }
    _transcript.addDtlsMessage(fullDtls);
    return _sendServerFlight();
  }

  /// Look at the client's `supported_groups` extension and pick the first
  /// group webdartc can speak. Returns null if there is no overlap or the
  /// extension is missing.
  int? _pickHrrGroup(ClientHelloMessage ch) {
    final sg = ch.extensionByType(TlsV13ExtensionType.supportedGroups);
    if (sg == null) return null;
    final groups = parseSupportedGroupsExtData(sg.data);
    if (groups == null) return null;
    for (final g in groups) {
      if (g == TlsV13NamedGroup.x25519 ||
          g == TlsV13NamedGroup.secp256r1) {
        return g;
      }
    }
    return null;
  }

  void _negotiateUseSrtp(ClientHelloMessage ch) {
    final useSrtp = ch.extensionByType(TlsV13ExtensionType.useSrtp);
    if (useSrtp != null) {
      final offered = parseUseSrtpExtData(useSrtp.data);
      if (offered != null) {
        _selectedSrtpProfile = _pickSrtpProfile(offered);
      }
    }
  }

  /// Emit a HelloRetryRequest for [selectedGroup], replace the transcript
  /// with `synthetic message_hash || HelloRetryRequest`
  /// (RFC 8446 §4.4.1), and transition to [waitSecondClientHello].
  ///
  /// The client is expected to resubmit a ClientHello carrying both the
  /// requested key_share and a verbatim copy of [_hrrCookie]; both are
  /// validated in [_handleSecondClientHello].
  core.Result<ProcessResult, core.ProtocolError> _sendHelloRetryRequest({
    required ClientHelloMessage ch,
    required Uint8List fullDtls,
    required TlsV13CipherSuite suite,
    required int selectedGroup,
  }) {
    _suite = suite;
    _selectedGroup = selectedGroup;
    _legacySessionIdEcho = ch.legacySessionId;
    _hrrCookie = Csprng.randomBytes(32);

    // Bind the original ClientHello into the transcript first, then
    // rewrite it as the RFC 8446 §4.4.1 synthetic message_hash so that
    // both sides can hash a deterministic prefix once HRR has been sent.
    _transcript.addDtlsMessage(fullDtls);
    _transcript.replaceWithSyntheticHash();

    final hrrExts = <TlsExtension>[
      TlsExtension(
        TlsV13ExtensionType.supportedVersions,
        buildServerHelloSupportedVersionsExtData(dtls13Version),
      ),
      TlsExtension(
        TlsV13ExtensionType.keyShare,
        buildHrrKeyShareExtData(selectedGroup),
      ),
      TlsExtension(
        TlsV13ExtensionType.cookie,
        buildCookieExtData(_hrrCookie!),
      ),
    ];
    final hrrBody = buildHelloRetryRequestBody(
      legacySessionIdEcho: ch.legacySessionId,
      cipherSuite: suite.id,
      extensions: hrrExts,
    );
    final hrrFull = wrapHandshake(
      msgType: TlsV13HandshakeType.serverHello,
      msgSeq: _outboundMsgSeq++,
      body: hrrBody,
    );
    _transcript.addDtlsMessage(hrrFull);

    _state = DtlsV13ServerState.waitSecondClientHello;
    return core.Ok(ProcessResult(
      outputPackets: [_emitPlaintextHandshake(hrrFull)],
    ));
  }

  /// Process the resubmitted ClientHello after [_sendHelloRetryRequest].
  /// The client must echo our cookie verbatim (RFC 8446 §4.2.2) and now
  /// supply a `key_share` for the group we demanded; otherwise the
  /// connection is rejected. On success the transcript already contains
  /// `synthetic_message_hash || HelloRetryRequest`, and we append CH2
  /// before delegating to the regular server-flight path.
  core.Result<ProcessResult, core.ProtocolError> _handleSecondClientHello(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    final ch = parseClientHello(body);
    if (ch == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad ClientHello (CH2)'));
    }

    // Validate cookie echo.
    final ce = ch.extensionByType(TlsV13ExtensionType.cookie);
    if (ce == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: CH2 missing cookie extension'),
      );
    }
    final cookie = parseCookieExtData(ce.data);
    if (cookie == null || _hrrCookie == null) {
      return core.Err(const core.ParseError('DTLS 1.3: CH2 cookie unparseable'));
    }
    if (cookie.length != _hrrCookie!.length) {
      return core.Err(const core.ParseError('DTLS 1.3: CH2 cookie mismatch'));
    }
    var diff = 0;
    for (var i = 0; i < cookie.length; i++) {
      diff |= cookie[i] ^ _hrrCookie![i];
    }
    if (diff != 0) {
      return core.Err(const core.ParseError('DTLS 1.3: CH2 cookie mismatch'));
    }

    // Now key_share must contain the group we demanded in HRR.
    final ks = ch.extensionByType(TlsV13ExtensionType.keyShare);
    if (ks == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: CH2 missing key_share'),
      );
    }
    final shares = parseClientHelloKeyShareExtData(ks.data);
    if (shares == null) {
      return core.Err(const core.ParseError('DTLS 1.3: CH2 bad key_share'));
    }
    final wanted = _selectedGroup!;
    KeyShareEntry? selected;
    for (final s in shares) {
      if (s.group == wanted) {
        selected = s;
        break;
      }
    }
    if (selected == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: CH2 missing requested key_share group'),
      );
    }
    final ok = (wanted == TlsV13NamedGroup.x25519 &&
            selected.keyExchange.length == 32) ||
        (wanted == TlsV13NamedGroup.secp256r1 &&
            selected.keyExchange.length == 65 &&
            selected.keyExchange[0] == 0x04);
    if (!ok) {
      return core.Err(
        const core.ParseError('DTLS 1.3: CH2 key_share has wrong format'),
      );
    }

    // Re-validate the suite — the client must select the same suite (or at
    // least one we still support) on retry.
    final suite = TlsV13CipherSuite.selectFromOffer(ch.cipherSuites);
    if (suite == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: CH2 has no overlapping cipher suite'),
      );
    }

    _negotiateUseSrtp(ch);
    return _completeClientHello(
      random: ch.random,
      legacySessionId: ch.legacySessionId,
      suite: suite,
      selectedGroup: wanted,
      peerKeyShare: selected.keyExchange,
      fullDtls: fullDtls,
    );
  }

  /// SRTP profiles webdartc supports, in server-preference order. Matches
  /// the DTLS 1.2 path's `_parseSrtpExtension` ordering: AEAD-GCM is
  /// preferred because it provides authenticated encryption in a single
  /// pass and is what current browsers prefer; AES-CM-HMAC-SHA1 is kept
  /// as an interop fallback (RFC 5764 §4.1.2 leaves profile choice to the
  /// server).
  static const List<int> _supportedSrtpProfiles = <int>[
    0x0007, // SRTP_AEAD_AES_128_GCM
    0x0008, // SRTP_AEAD_AES_256_GCM
    0x0001, // SRTP_AES128_CM_HMAC_SHA1_80
    0x0002, // SRTP_AES128_CM_HMAC_SHA1_32
  ];

  static int? _pickSrtpProfile(List<int> offered) {
    for (final id in _supportedSrtpProfiles) {
      if (offered.contains(id)) return id;
    }
    return null;
  }

  /// Bytes of TLS-exported keying material the negotiated SRTP profile
  /// expects. Layout is per RFC 5764 §4.2 / RFC 7714 §12.
  static int _srtpExportLengthForProfile(int profileId) {
    switch (profileId) {
      case 0x0001: // SRTP_AES128_CM_HMAC_SHA1_80
      case 0x0002: // SRTP_AES128_CM_HMAC_SHA1_32
        return 60; // 16 + 16 + 14 + 14
      case 0x0007: // SRTP_AEAD_AES_128_GCM
        return 56; // 16 + 16 + 12 + 12
      case 0x0008: // SRTP_AEAD_AES_256_GCM
        return 88; // 32 + 32 + 12 + 12
      default:
        // Unknown profile — fall back to the legacy 60-byte default; a
        // mis-sized export will surface as a key-derivation mismatch
        // rather than a silent truncation.
        return 60;
    }
  }

  core.Result<ProcessResult, core.ProtocolError> _sendServerFlight() {
    final suite = _suite!;
    final outputs = <OutputPacket>[];

    // ── ServerHello (plaintext, epoch 0) ────────────────────────────────
    final group = _selectedGroup!;
    final serverPublic = group == TlsV13NamedGroup.x25519
        ? _x25519KeyPair!.publicKeyBytes
        : _ecdhKeyPair!.publicKeyBytes;
    final shExts = <TlsExtension>[
      TlsExtension(
        TlsV13ExtensionType.supportedVersions,
        buildServerHelloSupportedVersionsExtData(dtls13Version),
      ),
      TlsExtension(
        TlsV13ExtensionType.keyShare,
        buildServerHelloKeyShareExtData(
          namedGroup: group,
          keyExchange: serverPublic,
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
    final Uint8List? ecdheShared;
    if (group == TlsV13NamedGroup.x25519) {
      ecdheShared = _x25519KeyPair!.computeSharedSecret(_peerKeyShare!);
    } else {
      ecdheShared = _ecdhKeyPair!.computeSharedSecret(_peerKeyShare!);
    }
    if (ecdheShared == null) {
      // RFC 8446 §7.4.2: low-order point — abort the handshake.
      return core.Err(
        const core.CryptoError('DTLS 1.3: ECDHE produced low-order point'),
      );
    }
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
    final eeExts = <TlsExtension>[
      if (_selectedSrtpProfile != null)
        TlsExtension(
          TlsV13ExtensionType.useSrtp,
          buildUseSrtpExtData(_selectedSrtpProfile!),
        ),
    ];
    _emitEncryptedHandshake(
      type: TlsV13HandshakeType.encryptedExtensions,
      body: buildEncryptedExtensionsBody(eeExts),
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
  //
  // Deferred: mTLS / client-authenticated handshake. This server never sends
  // CertificateRequest, so the client never produces a Certificate /
  // CertificateVerify pair that we'd need to verify here. Adding mTLS would
  // require sending CertificateRequest in the encrypted server flight,
  // accepting client Certificate / CertificateVerify before the client's
  // Finished, and verifying the CV signature with `EcdsaVerify` against the
  // pubkey extracted from the client cert. Tracked as a follow-up.

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
      // Size the TLS-exporter output to the negotiated SRTP profile
      // (RFC 7714 §12). When use_srtp wasn't negotiated we default to the
      // legacy 60-byte AES-CM length so existing tests / non-SRTP callers
      // keep working.
      final exportLen = _selectedSrtpProfile != null
          ? _srtpExportLengthForProfile(_selectedSrtpProfile!)
          : DtlsV13SrtpExport.srtpAes128CmHmacSha180Length;
      cb(DtlsV13SrtpExport.export(
        exporterMasterSecret: _exporterMasterSecret!,
        length: exportLen,
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

