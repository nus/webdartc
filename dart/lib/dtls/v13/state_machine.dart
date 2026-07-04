part of 'endpoint.dart';

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
final class DtlsV13ServerStateMachine extends DtlsV13Endpoint {
  /// Whether the server demands a client Certificate / CertificateVerify
  /// before completing the handshake (RFC 8446 §4.3.2 mid-handshake mTLS).
  /// When true, the server's flight includes a CertificateRequest and the
  /// client must supply its own Certificate + CertificateVerify before its
  /// Finished. When false (the default) the flow is unchanged from the
  /// non-mTLS case — the server doesn't ask, the client doesn't sign.
  final bool requireClientAuth;

  // ─── Public state observables ────────────────────────────────────────

  DtlsV13ServerState get state => _state;

  /// Server's 32-byte ServerHello.random — generated at construction time.
  Uint8List get serverRandom => _serverRandom;

  /// Client's ClientHello.random, available after the first ClientHello.
  Uint8List? get clientRandom => _clientRandom;

  // ─── Internal state ───────────────────────────────────────────────────

  DtlsV13ServerState _state = DtlsV13ServerState.initial;

  Uint8List? _clientRandom;
  final Uint8List _serverRandom = Csprng.randomBytes(32);
  Uint8List _legacySessionIdEcho = Uint8List(0);

  /// Persistent server secret used to MAC stateless HRR cookies (RFC 9147
  /// §5.1). Generated once per `DtlsV13ServerStateMachine` instance — the
  /// server-side v1.2 `DtlsStateMachine` that delegates to us spins up one
  /// instance per connection, so the key covers that connection's whole
  /// HRR exchange. Tests inject deterministic keys via the
  /// [DtlsV13ServerStateMachine.cookieMacKey] constructor parameter.
  final Uint8List _cookieMacKey;

  DtlsV13ServerStateMachine({
    required super.localCert,
    this.requireClientAuth = false,
    Uint8List? cookieMacKey,
  }) : _cookieMacKey = cookieMacKey ?? Csprng.randomBytes(32);

  // ─── Endpoint role hooks ──────────────────────────────────────────────

  @override
  bool get _isConnected => _state == DtlsV13ServerState.connected;

  @override
  void _markFailed() {
    _state = DtlsV13ServerState.failed;
  }

  @override
  bool get _rxUsesHandshakeKeys =>
      _state == DtlsV13ServerState.waitClientFinished ||
      _state == DtlsV13ServerState.waitClientCertificate ||
      _state == DtlsV13ServerState.waitClientCertificateVerify;

  @override
  bool get _retransmitPending =>
      _state == DtlsV13ServerState.waitSecondClientHello ||
      _state == DtlsV13ServerState.waitClientFinished ||
      _state == DtlsV13ServerState.waitClientCertificate ||
      _state == DtlsV13ServerState.waitClientCertificateVerify;

  @override
  core.ProtocolError get _retransmitLimitError => const core.StateError(
        'DTLS 1.3: server flight retransmit limit exceeded',
      );

  @override
  core.Result<ProcessResult, core.ProtocolError> _dispatchHandshakeMessage(
    int msgType,
    Uint8List body,
    Uint8List fullDtls,
  ) {
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
            _lastFlight != null) {
          // Client retransmitted: re-send our flight verbatim.
          return core.Ok(
            ProcessResult(outputPackets: List.of(_lastFlight!)),
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

  /// Peer key_share bytes from the accepted ClientHello, held until the
  /// server flight derives the ECDHE shared secret.
  Uint8List? _peerKeyShare;

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
    _records.suite = suite;
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
        _selectedSrtpProfile = SrtpProfileNegotiation.pick(
          offered,
          preference: SrtpProfileNegotiation.v13Preference,
        );
      }
    }
  }

  /// Emit a HelloRetryRequest for [selectedGroup], replace the transcript
  /// with `synthetic message_hash || HelloRetryRequest`
  /// (RFC 8446 §4.4.1), and transition to [waitSecondClientHello].
  ///
  /// The client is expected to resubmit a ClientHello carrying both the
  /// requested key_share and a verbatim copy of the cookie; both are
  /// validated in [_handleSecondClientHello].
  core.Result<ProcessResult, core.ProtocolError> _sendHelloRetryRequest({
    required ClientHelloMessage ch,
    required Uint8List fullDtls,
    required TlsV13CipherSuite suite,
    required int selectedGroup,
  }) {
    _records.suite = suite;
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
      clientIp: _records.remoteIp!.toCanonical(),
      clientPort: _records.remotePort!,
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
      msgSeq: _records.outboundMsgSeq++,
      body: hrrBody,
    );
    _transcript.addDtlsMessage(hrrFull);

    _state = DtlsV13ServerState.waitSecondClientHello;
    final flight = [_emitPlaintextHandshake(hrrFull)];
    return core.Ok(ProcessResult(
      outputPackets: flight,
      nextTimeout: _armFlightRetransmit(flight),
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
      clientIp: _records.remoteIp!.toCanonical(),
      clientPort: _records.remotePort!,
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
      msgSeq: _records.outboundMsgSeq++,
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
    _records.rxHandshakeKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: cHsTraffic,
      keyLength: suite.keyLength,
    );
    _records.txHandshakeKeys = TlsV13KeySchedule.deriveTrafficKeys(
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
    final serverFinishedVerifyData = HmacSha256.compute(
      _records.txHandshakeKeys!.finishedKey,
      _transcript.hash,
    );
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
    _records.rxApplicationKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: cAp,
      keyLength: suite.keyLength,
    );
    _records.txApplicationKeys = TlsV13KeySchedule.deriveTrafficKeys(
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
    return core.Ok(ProcessResult(
      outputPackets: outputs,
      nextTimeout: _armFlightRetransmit(outputs),
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
    final listLen = readU24(body, off);
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
    final certLen = readU24(body, off);
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
      final fp = Sha256.fingerprint(certDer);
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
    final scheme = readU16(body, 0);
    final sigLen = readU16(body, 2);
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
    final keys = _records.rxHandshakeKeys;
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
    if (!DtlsV13Endpoint._constantTimeEquals(expected, body)) {
      return core.Err(
        const core.CryptoError('DTLS 1.3: client Finished verify_data mismatch'),
      );
    }

    _transcript.addDtlsMessage(fullDtls);
    _state = DtlsV13ServerState.connected;
    _fireOnConnected();
    // Client Finished is the terminal flight from the client's
    // perspective — RFC 9147 §7.1 requires the receiver of a final
    // flight to send an ACK so the peer can clear its retransmit timer.
    final ackPkt = _emitAck([_records.lastRxRecordNumber!]);
    return core.Ok(ProcessResult(outputPackets: [ackPkt]));
  }

  // ─── Internal record-emission helpers ─────────────────────────────────

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
      msgSeq: _records.outboundMsgSeq++,
      body: body,
    );
    _transcript.addDtlsMessage(fragment);
    outputs.add(_records.encryptHandshake(fragment));
  }
}
