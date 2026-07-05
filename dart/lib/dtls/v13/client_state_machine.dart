part of 'endpoint.dart';

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
final class DtlsV13ClientStateMachine extends DtlsV13Endpoint {
  // ─── Public state observables ────────────────────────────────────────

  DtlsV13ClientState get state => _state;

  // ─── Internal state ───────────────────────────────────────────────────

  DtlsV13ClientState _state = DtlsV13ClientState.initial;

  final Uint8List _clientRandom = Csprng.randomBytes(32);
  final Uint8List _legacySessionId = Uint8List(0);

  /// SRTP profiles offered by the caller via [startHandshake]. When null,
  /// the use_srtp extension is omitted entirely.
  List<int>? _offeredSrtpProfiles;

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

  /// Cipher suites to advertise in ClientHello, in client-preference order.
  /// Defaults to AES-128-GCM first, ChaCha20-Poly1305 second — matching the
  /// implementation's primary suite while still letting the server pick
  /// ChaCha20 when it prefers (RFC 8446 §4.1.2).
  final List<int> offeredCipherSuites;

  DtlsV13ClientStateMachine({
    required super.localCert,
    this.offeredCipherSuites = const <int>[0x1301, 0x1303],
  });

  // ─── Endpoint role hooks ──────────────────────────────────────────────

  @override
  bool get _isConnected => _state == DtlsV13ClientState.connected;

  @override
  void _markFailed() {
    _state = DtlsV13ClientState.failed;
  }

  @override
  bool get _rxUsesHandshakeKeys => _state != DtlsV13ClientState.connected;

  @override
  bool get _retransmitPending =>
      _state != DtlsV13ClientState.connected &&
      _state != DtlsV13ClientState.failed &&
      _state != DtlsV13ClientState.initial;

  @override
  core.ProtocolError get _retransmitLimitError => const core.ProtocolStateError(
        'DTLS 1.3: client flight retransmit limit exceeded',
      );

  @override
  core.Result<ProcessResult, core.ProtocolError> _dispatchHandshakeMessage(
    int msgType,
    Uint8List body,
    Uint8List fullDtls,
  ) {
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

  // ─── Public start API ─────────────────────────────────────────────────

  /// Begin the handshake. Generates the initial ClientHello flight and
  /// transitions to [DtlsV13ClientState.sentClientHello].
  ///
  /// [supportedSrtpProfiles] is the list of RFC 5764 profile IDs to offer
  /// in `use_srtp`. Passing null omits the extension entirely.
  core.Result<ProcessResult, core.ProtocolError> startHandshake({
    required IpAddress remoteIp,
    required int remotePort,
    List<int>? supportedSrtpProfiles,
  }) {
    if (_state != DtlsV13ClientState.initial) {
      return core.Err(
        const core.ProtocolStateError('DTLS 1.3: startHandshake from non-initial state'),
      );
    }
    _records.remoteIp = remoteIp;
    _records.remotePort = remotePort;
    _offeredSrtpProfiles = supportedSrtpProfiles;
    _ecdhKeyPair = EcdhKeyPair.generate();
    _x25519KeyPair = X25519KeyPair.generate();

    final chFull = _buildClientHelloFlight(
      includeBothGroups: true,
      cookie: null,
    );
    _transcript.addDtlsMessage(chFull);
    _state = DtlsV13ClientState.sentClientHello;
    final flight = [_emitPlaintextHandshake(chFull)];
    return core.Ok(ProcessResult(
      outputPackets: flight,
      nextTimeout: _armFlightRetransmit(flight),
    ));
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
        buildClientHelloSupportedVersionsExtData(<int>[dtls13Version]),
      ),
      TlsExtension(
        TlsV13ExtensionType.supportedGroups,
        buildSupportedGroupsExtData(<int>[
          TlsV13NamedGroup.x25519,
          TlsV13NamedGroup.secp256r1,
        ]),
      ),
      TlsExtension(
        TlsV13ExtensionType.signatureAlgorithms,
        buildSignatureAlgorithmsExtData(<int>[
          TlsV13SignatureScheme.ecdsaSecp256r1Sha256,
        ]),
      ),
      TlsExtension(
        TlsV13ExtensionType.keyShare,
        buildClientHelloKeyShareExtData(
          _keyShareEntries(includeBothGroups: includeBothGroups),
        ),
      ),
      if (cookie != null)
        TlsExtension(
          TlsV13ExtensionType.cookie,
          buildCookieExtData(cookie),
        ),
      if (_offeredSrtpProfiles != null && _offeredSrtpProfiles!.isNotEmpty)
        TlsExtension(
          TlsV13ExtensionType.useSrtp,
          buildClientHelloUseSrtpExtData(_offeredSrtpProfiles!),
        ),
    ];

    final body = buildClientHelloBody(
      random: _clientRandom,
      legacySessionId: _legacySessionId,
      cookie: Uint8List(0),
      cipherSuites: offeredCipherSuites,
      extensions: exts,
    );
    return wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: _records.outboundMsgSeq++,
      body: body,
    );
  }

  /// KeyShareEntry list for the ClientHello key_share extension. When
  /// [includeBothGroups] is true (CH1), both x25519 and secp256r1 entries
  /// are sent — most recent browsers emit both because either can be
  /// preferred by the server. When false (CH2 after HRR), only the
  /// [_selectedGroup] entry is sent.
  List<KeyShareEntry> _keyShareEntries({required bool includeBothGroups}) {
    if (includeBothGroups) {
      return <KeyShareEntry>[
        KeyShareEntry(
          group: TlsV13NamedGroup.x25519,
          keyExchange: _x25519KeyPair!.publicKeyBytes,
        ),
        KeyShareEntry(
          group: TlsV13NamedGroup.secp256r1,
          keyExchange: _ecdhKeyPair!.publicKeyBytes,
        ),
      ];
    }
    final g = _selectedGroup!;
    return <KeyShareEntry>[
      KeyShareEntry(
        group: g,
        keyExchange: g == TlsV13NamedGroup.x25519
            ? _x25519KeyPair!.publicKeyBytes
            : _ecdhKeyPair!.publicKeyBytes,
      ),
    ];
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
    _records.suite = suite;

    final svExt = _findExtension(sh.extensions, TlsV13ExtensionType.supportedVersions);
    if (svExt == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: ServerHello missing supported_versions'),
      );
    }
    if (svExt.data.length != 2 || readU16(svExt.data, 0) != dtls13Version) {
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
    final group = readU16(ksExt.data, 0);
    final keLen = readU16(ksExt.data, 2);
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
    _records.txHandshakeKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: TlsV13KeySchedule.computeClientHandshakeTrafficSecret(
        handshakeSecret: _handshakeSecret!,
        chShTranscriptHash: chShHash,
      ),
      keyLength: suite.keyLength,
    );
    _records.rxHandshakeKeys = TlsV13KeySchedule.deriveTrafficKeys(
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
    _records.suite = suite;

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
    final flight = [_emitPlaintextHandshake(ch2Full)];
    return core.Ok(ProcessResult(
      outputPackets: flight,
      nextTimeout: _armFlightRetransmit(flight),
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
    final listLen = readU24(body, off);
    off += 3;
    if (off + listLen != body.length || listLen == 0) {
      return core.Err(const core.ParseError('DTLS 1.3: bad Certificate list'));
    }
    // First CertificateEntry: cert_data_len(3) || cert_data || extensions_len(2) || extensions.
    if (off + 3 > body.length) {
      return core.Err(const core.ParseError('DTLS 1.3: bad CertificateEntry'));
    }
    final certLen = readU24(body, off);
    off += 3;
    if (off + certLen > body.length) {
      return core.Err(const core.ParseError('DTLS 1.3: truncated cert_data'));
    }
    final certDer = Uint8List.sublistView(body, off, off + certLen);

    final expected = expectedRemoteFingerprint;
    if (expected != null) {
      final fp = Sha256.fingerprint(certDer);
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
    final scheme = readU16(body, 0);
    final sigLen = readU16(body, 2);
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
        const core.ProtocolStateError(
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
    final keys = _records.rxHandshakeKeys;
    if (keys == null) {
      return core.Err(
        const core.ProtocolStateError('DTLS 1.3: server Finished before keys'),
      );
    }
    final expected = HmacSha256.compute(keys.finishedKey, _transcript.hash);
    if (body.length != expected.length) {
      return core.Err(
        const core.CryptoError('DTLS 1.3: server Finished wrong length'),
      );
    }
    if (!constantTimeEquals(expected, body)) {
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
    _records.txApplicationKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: cAp,
      keyLength: _suite!.keyLength,
    );
    _records.rxApplicationKeys = TlsV13KeySchedule.deriveTrafficKeys(
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
        msgSeq: _records.outboundMsgSeq++,
        body: buildCertificateBody(
          certificateRequestContext: _certificateRequestContext,
          certDerChain: <Uint8List>[localCert.derBytes],
        ),
      );
      _transcript.addDtlsMessage(certFragment);
      outputs.add(_records.encryptHandshake(certFragment));

      final cvSigned = certificateVerifySignedContent(
        transcriptHash: _transcript.hash,
        isServer: false,
      );
      final cvSignature = localCert.sign(cvSigned);
      final cvFragment = wrapHandshake(
        msgType: TlsV13HandshakeType.certificateVerify,
        msgSeq: _records.outboundMsgSeq++,
        body: buildCertificateVerifyBody(
          signatureScheme: TlsV13SignatureScheme.ecdsaSecp256r1Sha256,
          signature: cvSignature,
        ),
      );
      _transcript.addDtlsMessage(cvFragment);
      outputs.add(_records.encryptHandshake(cvFragment));
    }

    // Build & send client Finished (epoch 2, encrypted with client_hs).
    final clientVerifyData = HmacSha256.compute(
      _records.txHandshakeKeys!.finishedKey,
      _transcript.hash,
    );
    final finFragment = wrapHandshake(
      msgType: TlsV13HandshakeType.finished,
      msgSeq: _records.outboundMsgSeq++,
      body: buildFinishedBody(clientVerifyData),
    );
    outputs.add(_records.encryptHandshake(finFragment));

    _state = DtlsV13ClientState.connected;
    _fireOnConnected();
    return core.Ok(ProcessResult(outputPackets: outputs));
  }
}
