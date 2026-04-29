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
import 'cookie.dart';
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

  /// Server flight has been emitted with a CertificateRequest;
  /// awaiting the client's encrypted Certificate on epoch 2. Only
  /// reached when [DtlsV13ServerStateMachine.requireClientAuth] is true.
  waitClientCertificate,

  /// Client Certificate has been received; awaiting the client's
  /// CertificateVerify on epoch 2. Only reached when client auth is
  /// required.
  waitClientCertificateVerify,

  /// Server flight (ServerHello + EncryptedExtensions + [CertificateRequest] +
  /// Certificate + CertificateVerify + Finished) has been emitted; awaiting
  /// the client's encrypted Finished on epoch 2.
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

  /// Whether the server demands a client Certificate / CertificateVerify
  /// before completing the handshake (RFC 8446 §4.3.2 mid-handshake mTLS).
  /// When true, the server's flight includes a CertificateRequest and the
  /// client must supply its own Certificate + CertificateVerify before its
  /// Finished. When false (the default) the flow is unchanged from the
  /// non-mTLS case — the server doesn't ask, the client doesn't sign.
  final bool requireClientAuth;

  /// Expected SHA-256 fingerprint of the *peer's* certificate, formatted
  /// as colon-separated uppercase hex (matching the SDP `a=fingerprint`
  /// convention used by [EcdsaCertificate.sha256Fingerprint]). When
  /// non-null, the server compares this to the client's actual cert
  /// fingerprint after parsing the client Certificate; mismatch fails the
  /// handshake with a `CryptoError`. When null, no check is performed.
  /// Only meaningful with [requireClientAuth] true.
  String? expectedRemoteFingerprint;

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

  /// Number of retransmissions performed for the current outbound flight
  /// (RFC 9147 §5.7). Reset whenever a new flight is sent (HRR or main
  /// server flight). Each handleTimeout fire bumps this and reschedules
  /// the next timer with exponential backoff.
  int _handshakeRetransmitCount = 0;

  /// RFC 9147 §5.7 caps the total retransmission window at "implementation
  /// defined". 6 retries with 1s base ⇒ 1+2+4+8+16+32 = 63s ceiling, which
  /// matches the legacy v1.2 path and is well under WebRTC ICE-consent
  /// freshness.
  static const int _maxHandshakeRetransmits = 6;
  static const int _initialHandshakeRetransmitMs = 1000;

  /// Record number of the last successfully decrypted inbound record,
  /// captured right before handshake dispatch so that handlers (Finished,
  /// KeyUpdate) can build an ACK referencing it without re-plumbing the
  /// decrypt result through every dispatch path (RFC 9147 §7.1).
  DtlsAckRecordNumber? _lastRxRecordNumber;

  /// Current application-data tx epoch (RFC 9147 §6.1). Starts at 3 once
  /// the handshake completes and increments by one each time we emit a
  /// KeyUpdate. The truncated value carried in record headers is
  /// `_txAppEpoch & 0x03`.
  int _txAppEpoch = 3;

  /// Current application-data rx epoch. Starts at 3 and increments by one
  /// each time we successfully process a peer KeyUpdate.
  int _rxAppEpoch = 3;

  /// True after we've received a KeyUpdate(update_requested) from the
  /// peer; we owe them a reciprocal KeyUpdate before our next
  /// application_data record (RFC 8446 §4.6.3). Cleared on emission.
  bool _peerRequestedKeyUpdate = false;

  /// The most recently emitted server flight, kept so we can re-send it on
  /// receipt of a duplicate ClientHello (RFC 6347-style retransmit).
  List<OutputPacket>? _lastServerFlight;

  /// In-progress handshake message reassembly. Keyed by `messageSeq`. Each
  /// entry buffers the full message body until every fragment has arrived
  /// (RFC 9147 §5.5).
  final Map<int, _Reassembly> _fragmentBuffer = <int, _Reassembly>{};

  /// Persistent server secret used to MAC stateless HRR cookies (RFC 9147
  /// §5.1). Generated once per `DtlsV13ServerStateMachine` instance — the
  /// DtlsServerDispatcher in front of us is process-scoped, so a single
  /// key covers every connection it handles. Tests inject deterministic
  /// keys via the [DtlsV13ServerStateMachine.cookieMacKey] constructor
  /// parameter.
  final Uint8List _cookieMacKey;

  DtlsV13ServerStateMachine({
    required this.localCert,
    this.requireClientAuth = false,
    Uint8List? cookieMacKey,
  }) : _cookieMacKey = cookieMacKey ?? Csprng.randomBytes(32);

  /// 65-byte uncompressed P-256 pubkey extracted from the client's
  /// Certificate message. Set during [_handleClientCertificate]; null
  /// before that, and always null when [requireClientAuth] is false.
  Uint8List? _peerCertPubKey;

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
    if (token is! DtlsRetransmitToken) {
      return const core.Ok(ProcessResult.empty);
    }
    // Only retransmit while we are still waiting on the peer to advance
    // the handshake. Once the handshake transitions away from the post-
    // send waiting states (or fails), drop the timer silently — the next
    // _scheduleTimeout call from a real event will replace it.
    final waiting = _state == DtlsV13ServerState.waitSecondClientHello ||
        _state == DtlsV13ServerState.waitClientFinished ||
        _state == DtlsV13ServerState.waitClientCertificate ||
        _state == DtlsV13ServerState.waitClientCertificateVerify;
    if (!waiting) return const core.Ok(ProcessResult.empty);
    final flight = _lastServerFlight;
    if (flight == null) return const core.Ok(ProcessResult.empty);
    if (_handshakeRetransmitCount >= _maxHandshakeRetransmits) {
      _state = DtlsV13ServerState.failed;
      return core.Err(const core.StateError(
        'DTLS 1.3: server flight retransmit limit exceeded',
      ));
    }
    _handshakeRetransmitCount += 1;
    return core.Ok(ProcessResult(
      outputPackets: List.of(flight),
      nextTimeout: _nextHandshakeRetransmitTimeout(),
    ));
  }

  /// Compute the next exponential-backoff timeout for the active flight
  /// (RFC 9147 §5.7 / RFC 6347 §4.2.4.1). Base 1s, doubling per attempt,
  /// capped at 60s.
  Timeout _nextHandshakeRetransmitTimeout() {
    final delayMs = (_initialHandshakeRetransmitMs *
            (1 << _handshakeRetransmitCount))
        .clamp(0, 60000);
    return Timeout(
      at: DateTime.now().add(Duration(milliseconds: delayMs)),
      token: DtlsRetransmitToken(0),
    );
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
    return _processHandshakeFragments(rec.fragment);
  }

  core.Result<ProcessResult, core.ProtocolError> _processCiphertextRecord(
    Uint8List packet,
  ) {
    final isHandshakeEpoch = _state == DtlsV13ServerState.waitClientFinished ||
        _state == DtlsV13ServerState.waitClientCertificate ||
        _state == DtlsV13ServerState.waitClientCertificateVerify;
    final keys = isHandshakeEpoch ? _clientHsKeys : _clientApKeys;
    if (keys == null) return const core.Ok(ProcessResult.empty);

    final epoch = isHandshakeEpoch ? 2 : _rxAppEpoch;
    final out = DtlsV13RecordCrypto.decrypt(
      record: packet,
      keys: keys,
      epoch: epoch,
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
    );
    if (out == null) {
      // RFC 9147 §4.5.3: silently drop unauthenticatable records.
      return const core.Ok(ProcessResult.empty);
    }
    _lastRxRecordNumber = DtlsAckRecordNumber(epoch, out.seqNum);
    switch (out.contentType) {
      case DtlsContentType.handshake:
        return _processHandshakeFragments(out.content);
      case DtlsContentType.applicationData:
        if (_state == DtlsV13ServerState.connected) {
          onApplicationData?.call(out.content);
        }
        return const core.Ok(ProcessResult.empty);
      case DtlsContentType.ack:
        // RFC 9147 §7: parse and discard. We do not yet maintain a
        // per-record retransmit queue to clear, so received ACKs are
        // informational only. Malformed bodies are silently dropped per
        // §4.5.3 (unauthenticatable / unexpected records).
        parseAckRecord(out.content);
        return const core.Ok(ProcessResult.empty);
      case DtlsContentType.alert:
        _state = DtlsV13ServerState.failed;
        return const core.Ok(ProcessResult.empty);
      default:
        return const core.Ok(ProcessResult.empty);
    }
  }

  // ─── Handshake message dispatch ───────────────────────────────────────

  /// Walk a buffer that may carry one or more concatenated DTLS handshake
  /// records. WebRTC peers (notably Firefox) bundle the client response
  /// flight — `Certificate || CertificateVerify || Finished` — into a
  /// single ciphertext record, so the server has to keep dispatching
  /// successive fragments until the buffer is exhausted.
  core.Result<ProcessResult, core.ProtocolError> _processHandshakeFragments(
    Uint8List buf,
  ) {
    final outputs = <OutputPacket>[];
    Timeout? lastTimeout;
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
      final r = _processHandshakeFragment(slice);
      if (r.isErr) return r;
      outputs.addAll(r.value.outputPackets);
      // Last non-null nextTimeout wins; flight-emitting handlers set this
      // so the upper layer can schedule a retransmit timer (RFC 9147 §5.7).
      if (r.value.nextTimeout != null) lastTimeout = r.value.nextTimeout;
      offset += total;
    }
    return core.Ok(
      ProcessResult(outputPackets: outputs, nextTimeout: lastTimeout),
    );
  }

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
        if ((_state == DtlsV13ServerState.waitClientFinished ||
                _state == DtlsV13ServerState.waitClientCertificate ||
                _state == DtlsV13ServerState.waitClientCertificateVerify) &&
            _lastServerFlight != null) {
          // Client retransmitted: re-send our flight verbatim.
          return core.Ok(
            ProcessResult(outputPackets: List.of(_lastServerFlight!)),
          );
        }
        return const core.Ok(ProcessResult.empty);

      case TlsV13HandshakeType.certificate:
        if (_state != DtlsV13ServerState.waitClientCertificate) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleClientCertificate(body, fullDtls);

      case TlsV13HandshakeType.certificateVerify:
        if (_state != DtlsV13ServerState.waitClientCertificateVerify) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleClientCertificateVerify(body, fullDtls);

      case TlsV13HandshakeType.finished:
        if (_state != DtlsV13ServerState.waitClientFinished) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleClientFinished(body, fullDtls);

      case TlsV13HandshakeType.keyUpdate:
        if (_state != DtlsV13ServerState.connected) {
          return const core.Ok(ProcessResult.empty);
        }
        return _handleKeyUpdate(body);

      default:
        return const core.Ok(ProcessResult.empty);
    }
  }

  /// Handle a peer KeyUpdate (RFC 8446 §4.6.3 / RFC 9147 §6.1):
  /// rotate the rx application keys to the next generation, bump
  /// `_rxAppEpoch`, ACK the KeyUpdate record (RFC 9147 §7 — KeyUpdate
  /// is non-eliciting, so the only signal back is an ACK), and (if the
  /// peer set `update_requested`) record that we owe a reciprocal
  /// KeyUpdate before our next application_data.
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
      _clientApKeys!.trafficSecret,
    );
    _clientApKeys = TlsV13KeySchedule.deriveTrafficKeys(
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

    // Bind the original ClientHello into the transcript first, then
    // rewrite it as the RFC 8446 §4.4.1 synthetic message_hash so that
    // both sides can hash a deterministic prefix once HRR has been sent.
    _transcript.addDtlsMessage(fullDtls);
    // Snapshot the CH1 transcript hash *before* the synthetic-hash
    // rewrite — this is what the cookie carries so a CH2 can be
    // validated without retaining CH1 itself (RFC 9147 §5.1).
    final ch1Hash = _transcript.hash;
    _transcript.replaceWithSyntheticHash();

    final cookie = DtlsV13Cookie.mint(
      macKey: _cookieMacKey,
      transcriptHashCh1: ch1Hash,
      clientIp: _remoteIp!,
      clientPort: _remotePort!,
    );

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
        buildCookieExtData(cookie),
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
    final flight = [_emitPlaintextHandshake(hrrFull)];
    _lastServerFlight = List.of(flight);
    _handshakeRetransmitCount = 0;
    return core.Ok(ProcessResult(
      outputPackets: flight,
      nextTimeout: _nextHandshakeRetransmitTimeout(),
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

    // Validate cookie echo. RFC 9147 §5.1: the cookie itself is
    // self-validating (HMAC over CH1 transcript hash + endpoint id) so
    // we don't need to retain any per-client CH1 state — the only
    // long-lived secret is _cookieMacKey.
    final ce = ch.extensionByType(TlsV13ExtensionType.cookie);
    if (ce == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: CH2 missing cookie extension'),
      );
    }
    final cookie = parseCookieExtData(ce.data);
    if (cookie == null) {
      return core.Err(const core.ParseError('DTLS 1.3: CH2 cookie unparseable'));
    }
    final opened = DtlsV13Cookie.open(
      macKey: _cookieMacKey,
      cookie: cookie,
      clientIp: _remoteIp!,
      clientPort: _remotePort!,
    );
    if (opened == null || !opened.isValid) {
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
    if (requireClientAuth) {
      _emitEncryptedHandshake(
        type: TlsV13HandshakeType.certificateRequest,
        body: buildCertificateRequestBody(
          certificateRequestContext: Uint8List(0),
          extensions: <TlsExtension>[
            TlsExtension(
              TlsV13ExtensionType.signatureAlgorithms,
              buildSignatureAlgorithmsExtData(<int>[
                TlsV13SignatureScheme.ecdsaSecp256r1Sha256,
              ]),
            ),
          ],
        ),
        outputs: outputs,
      );
    }
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

    _state = requireClientAuth
        ? DtlsV13ServerState.waitClientCertificate
        : DtlsV13ServerState.waitClientFinished;
    _lastServerFlight = List.of(outputs);
    _handshakeRetransmitCount = 0;
    return core.Ok(ProcessResult(
      outputPackets: outputs,
      nextTimeout: _nextHandshakeRetransmitTimeout(),
    ));
  }

  // ─── client Certificate / CertificateVerify (mTLS) ────────────────────

  core.Result<ProcessResult, core.ProtocolError> _handleClientCertificate(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    // RFC 8446 §4.4.2 Certificate body:
    //   opaque certificate_request_context<0..255>;
    //   CertificateEntry certificate_list<0..2^24-1>;
    if (body.isEmpty) {
      return core.Err(
        const core.ParseError('DTLS 1.3: empty client Certificate'),
      );
    }
    final ctxLen = body[0];
    if (1 + ctxLen + 3 > body.length) {
      return core.Err(
        const core.ParseError('DTLS 1.3: bad client Certificate context'),
      );
    }
    var off = 1 + ctxLen;
    final listLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2];
    off += 3;
    if (off + listLen != body.length) {
      return core.Err(
        const core.ParseError('DTLS 1.3: bad client Certificate list'),
      );
    }
    if (listLen == 0) {
      // RFC 8446 §4.4.2: client Certificate may be empty when the client
      // does not have a usable cert, but for our mTLS path we treat that
      // as a failure — the SDP a=fingerprint contract requires both sides
      // to present a verifiable cert.
      return core.Err(
        const core.CryptoError('DTLS 1.3: client Certificate is empty'),
      );
    }
    if (off + 3 > body.length) {
      return core.Err(
        const core.ParseError('DTLS 1.3: bad client CertificateEntry'),
      );
    }
    final certLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2];
    off += 3;
    if (off + certLen > body.length) {
      return core.Err(
        const core.ParseError('DTLS 1.3: truncated client cert_data'),
      );
    }
    final certDer = Uint8List.fromList(
      body.sublist(off, off + certLen),
    );

    // Verify SDP a=fingerprint binding when the caller has set one. The
    // format mirrors EcdsaCertificate.sha256Fingerprint — colon-separated
    // uppercase hex.
    final expected = expectedRemoteFingerprint;
    if (expected != null) {
      final fp = Sha256.hash(certDer)
          .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
          .join(':');
      if (fp != expected) {
        return core.Err(
          const core.CryptoError(
              'DTLS 1.3: client cert fingerprint mismatch'),
        );
      }
    }

    final pub = extractEcdsaP256PublicKey(certDer);
    if (pub == null) {
      return core.Err(
        const core.CryptoError(
            'DTLS 1.3: client cert is not P-256 ecPublicKey'),
      );
    }
    _peerCertPubKey = pub;

    _transcript.addDtlsMessage(fullDtls);
    _state = DtlsV13ServerState.waitClientCertificateVerify;
    return const core.Ok(ProcessResult.empty);
  }

  core.Result<ProcessResult, core.ProtocolError> _handleClientCertificateVerify(
    Uint8List body,
    Uint8List fullDtls,
  ) {
    if (body.length < 4) {
      return core.Err(
        const core.ParseError('DTLS 1.3: short client CertificateVerify'),
      );
    }
    final scheme = (body[0] << 8) | body[1];
    final sigLen = (body[2] << 8) | body[3];
    if (4 + sigLen != body.length) {
      return core.Err(
        const core.ParseError('DTLS 1.3: bad client CertificateVerify'),
      );
    }
    if (scheme != TlsV13SignatureScheme.ecdsaSecp256r1Sha256) {
      return core.Err(
        const core.CryptoError(
            'DTLS 1.3: client CertificateVerify scheme not supported'),
      );
    }
    final signature = body.sublist(4, 4 + sigLen);

    final peerPub = _peerCertPubKey;
    if (peerPub == null) {
      return core.Err(
        const core.StateError(
            'DTLS 1.3: client CertificateVerify before Certificate'),
      );
    }
    final signedContent = certificateVerifySignedContent(
      transcriptHash: _transcript.hash,
      isServer: false,
    );
    final ok = EcdsaVerify.verifyP256Sha256(
      publicKey: peerPub,
      message: signedContent,
      signature: signature,
    );
    if (!ok) {
      return core.Err(
        const core.CryptoError(
            'DTLS 1.3: client CertificateVerify failed'),
      );
    }

    _transcript.addDtlsMessage(fullDtls);
    _state = DtlsV13ServerState.waitClientFinished;
    return const core.Ok(ProcessResult.empty);
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
    // Client Finished is the terminal flight from the client's
    // perspective — RFC 9147 §7.1 requires the receiver of a final
    // flight to send an ACK so the peer can clear its retransmit timer.
    final ackPkt = _emitAck([_lastRxRecordNumber!]);
    return core.Ok(ProcessResult(outputPackets: [ackPkt]));
  }

  /// Encrypt and emit an ACK record (RFC 9147 §7) at the current tx app
  /// epoch using the server's app keys. Caller supplies the (epoch, seq)
  /// pairs to acknowledge.
  OutputPacket _emitAck(List<DtlsAckRecordNumber> records) {
    final body = buildAckRecord(records);
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.ack,
      content: body,
      epoch: _txAppEpoch,
      seqNum: _sendSeqEpoch3++,
      keys: _serverApKeys!,
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
    );
    return OutputPacket(
      data: rec,
      remoteIp: _remoteIp!,
      remotePort: _remotePort!,
    );
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
    final outputs = <OutputPacket>[];
    if (_peerRequestedKeyUpdate) {
      outputs.add(_emitKeyUpdate(KeyUpdateRequest.notRequested));
    }
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.applicationData,
      content: data,
      epoch: _txAppEpoch,
      seqNum: _sendSeqEpoch3++,
      keys: _serverApKeys!,
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
  /// §6.1). Emits the message under the current tx app keys, then rotates
  /// our own application-data sender to the next-generation keys / epoch.
  ///
  /// [requestPeerUpdate] sets the `KeyUpdateRequest` field to
  /// `update_requested(1)`; the peer must reciprocate before its next
  /// application_data record.
  core.Result<ProcessResult, core.ProtocolError> requestKeyUpdate({
    bool requestPeerUpdate = false,
  }) {
    if (_state != DtlsV13ServerState.connected) {
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
  /// current tx app keys. After the record is on the wire the next-gen
  /// secret + keys are derived and tx epoch / sequence are bumped per
  /// RFC 9147 §6.1.
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
      keys: _serverApKeys!,
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
    );
    // Rotate our sender to the next generation. The KeyUpdate itself was
    // sent under the old keys; everything after this point uses the new.
    final nextSecret = TlsV13KeySchedule.deriveNextTrafficSecret(
      _serverApKeys!.trafficSecret,
    );
    _serverApKeys = TlsV13KeySchedule.deriveTrafficKeys(
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
      cipherSuite: _suite ?? TlsV13CipherSuite.aes128GcmSha256,
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

