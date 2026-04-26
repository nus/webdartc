import 'dart:io' show Platform, stderr;
import 'dart:typed_data';

import '../core/state_machine.dart';
import '../crypto/csprng.dart';
import '../crypto/ecdh.dart';
import '../crypto/ecdsa.dart';
import '../crypto/sha256.dart';
import '../crypto/x509_der.dart';
import 'cipher_suite.dart';
import 'handshake.dart';
import 'key_material.dart';
import 'record.dart';
import 'v13/handshake.dart' as v13;
import 'v13/state_machine.dart' as v13;

export 'cipher_suite.dart' show CipherSuite;

/// DTLS role.
enum DtlsRole { client, server }

/// DTLS 1.2 state machine (RFC 6347).
///
/// Implements both client and server sides of the DTLS handshake.
/// Pure state machine — no I/O.
final class DtlsStateMachine implements ProtocolStateMachine {
  DtlsRole role;
  final EcdsaCertificate localCert;

  DtlsHandshakeState _state = DtlsHandshakeState.initial;

  // Remote address (set on first processInput call)
  String _remoteIp = '';
  int _remotePort = 0;

  // Handshake state
  late Uint8List _clientRandom;
  Uint8List? _serverRandom;
  Uint8List? _cookie;
  Uint8List? _sessionId;
  Uint8List?
  _peerPublicKeyBytes; // peer EC public key (from cert or key exchange)
  /// Peer cert's public key, parsed from the Certificate message. Used to
  /// verify ServerKeyExchange (client side) and CertificateVerify (server
  /// side) signatures.
  Uint8List? _peerCertPubKey;
  EcdhKeyPair? _ecdhKeyPair;
  Uint8List? _masterSecret;
  DtlsKeyBlock? _keyBlock;
  final _transcript = HandshakeTranscript();

  // Fragment reassembly: (msgType, messageSeq) → accumulated fragments
  final _fragmentBuffer = <int, _FragmentAssembler>{};

  // Duplicate detection: track received handshake (msgType, messageSeq) pairs.
  // _receivedHandshake: messages already added to transcript (avoid double-add).
  // _processedHandshake: messages whose handlers succeeded (skip on retransmit).
  final _receivedHandshake = <int>{};
  final _processedHandshake = <int>{};

  // In-order processing buffer (RFC 6347 §4.1.1.1): buffer out-of-order
  // messages and process them in message sequence order.
  int _nextExpectedMsgSeq = 0;
  final _reorderBuffer = <int, (int, Uint8List, Uint8List)>{}; // msgSeq → (msgType, body, fullFragment)

  // Record layer state
  int _sendEpoch = 0;
  int _sendSeq = 0;
  int _recvEpoch = 0; // ignore: unused_field — reserved for epoch validation
  int _msgSeqCounter = 0;

  // Debug logging
  static final bool _debug = Platform.environment['WEBDARTC_DEBUG'] == '1';

  // Selected cipher suite
  CipherSuite _negotiatedSuite = CipherSuite.ecdhEcdsaAes128GcmSha256;

  // Retransmit buffer (last flight)
  List<Uint8List>? _lastFlight;
  int _retransmitCount = 0;
  static const int _maxRetransmit = 7;

  /// Expected remote fingerprint (set from SDP a=fingerprint before connecting).
  String? expectedRemoteFingerprint;

  /// Called when DTLS handshake completes.
  ///
  /// [keyMaterial] is the exported SRTP key material (60 bytes for AES-128-CM).
  void Function(Uint8List keyMaterial)? onConnected;

  /// Called when application data is received.
  void Function(Uint8List data)? onApplicationData;

  /// When the very first ClientHello on the server side advertises DTLS 1.3
  /// (`supported_versions` extension contains `0xFEFC`), all further record
  /// processing is delegated to a freshly-spun [v13.DtlsV13ServerStateMachine].
  /// While this is non-null, the legacy DTLS 1.2 paths in this class are
  /// bypassed entirely. `null` for client mode and for DTLS 1.2 clients.
  v13.DtlsV13ServerStateMachine? _v13Inner;

  DtlsStateMachine({required this.role, required this.localCert});

  DtlsHandshakeState get state => _state;

  /// Start the DTLS handshake (client only — sends ClientHello).
  Result<ProcessResult, ProtocolError> startHandshake({
    required String remoteIp,
    required int remotePort,
  }) {
    if (role != DtlsRole.client) {
      return Err(const StateError('DTLS: only client can initiate handshake'));
    }
    _remoteIp = remoteIp;
    _remotePort = remotePort;
    return _sendClientHello();
  }

  /// Send application data (post-handshake).
  Result<ProcessResult, ProtocolError> sendApplicationData(
    Uint8List plaintext,
  ) {
    final v13Inner = _v13Inner;
    if (v13Inner != null) {
      return v13Inner.sendApplicationData(plaintext);
    }
    if (_state != DtlsHandshakeState.connected) {
      return Err(const StateError('DTLS: not connected'));
    }
    final record = _encryptRecord(DtlsContentType.applicationData, plaintext);
    return Ok(
      ProcessResult(
        outputPackets: [
          OutputPacket(
            data: record,
            remoteIp: _remoteIp,
            remotePort: _remotePort,
          ),
        ],
      ),
    );
  }

  @override
  Result<ProcessResult, ProtocolError> processInput(
    Uint8List packet, {
    required String remoteIp,
    required int remotePort,
  }) {
    _remoteIp = remoteIp;
    _remotePort = remotePort;

    // If we've already committed to the DTLS 1.3 path, all subsequent
    // datagrams flow through the v1.3 state machine verbatim.
    final v13Inner = _v13Inner;
    if (v13Inner != null) {
      return v13Inner.processInput(packet,
          remoteIp: remoteIp, remotePort: remotePort);
    }

    // Detect DTLS 1.3 on the very first server-side ClientHello and hand
    // the rest of the session over to the v1.3 state machine.
    if (role == DtlsRole.server &&
        _state == DtlsHandshakeState.initial &&
        _isDtls13ClientHello(packet)) {
      final inner = v13.DtlsV13ServerStateMachine(localCert: localCert);
      inner.onConnected = (km) => onConnected?.call(km);
      inner.onApplicationData = (data) => onApplicationData?.call(data);
      _v13Inner = inner;
      return inner.processInput(packet,
          remoteIp: remoteIp, remotePort: remotePort);
    }

    // Parse record layer
    var offset = 0;
    final results = <OutputPacket>[];
    Timeout? nextTimeout;

    while (offset < packet.length) {
      final record = DtlsRecord.parse(packet, offset);
      if (record == null) break;
      offset += 13 + record.fragment.length;

      try {
        final result = _processRecord(record);
        if (result.isErr) {
          if (_debug) {
            stderr.writeln('[dtls] processRecord ERROR: ${result.error}');
          }
          return Err(result.error);
        }
        results.addAll(result.value.outputPackets);
        nextTimeout = result.value.nextTimeout ?? nextTimeout;
      } catch (e, st) {
        if (_debug) {
          stderr.writeln('[dtls] processRecord EXCEPTION: $e');
          stderr.writeln('[dtls] $st');
        }
        return Err(CryptoError('DTLS exception: $e'));
      }
    }

    return Ok(ProcessResult(outputPackets: results, nextTimeout: nextTimeout));
  }

  @override
  Result<ProcessResult, ProtocolError> handleTimeout(TimerToken token) {
    final v13Inner = _v13Inner;
    if (v13Inner != null) return v13Inner.handleTimeout(token);
    if (token is DtlsRetransmitToken) {
      return _retransmit(token.epoch);
    }
    return const Ok(ProcessResult.empty);
  }

  /// Peek into the very first server-side packet to decide whether the
  /// rest of the session should be handled by the DTLS 1.3 server state
  /// machine instead of the legacy 1.2 paths in this class.
  ///
  /// Returns true iff the packet is a server-bound ClientHello that either
  /// (a) is fragmented — almost certainly DTLS 1.3 in practice, since v1.2
  /// ClientHellos are small enough to fit a single record — or (b) has a
  /// `supported_versions` extension listing `0xFEFC` (DTLS 1.3). The
  /// fragmented heuristic is needed for WebRTC clients (Firefox, Chrome)
  /// whose DTLS 1.3 ClientHellos exceed the path MTU and split across
  /// multiple datagrams; we route them to the v1.3 path immediately so
  /// that state machine can reassemble before parsing.
  static bool _isDtls13ClientHello(Uint8List packet) {
    final rec = DtlsRecord.parse(packet, 0);
    if (rec == null) return false;
    if (rec.epoch != 0) return false;
    if (rec.contentType != DtlsContentType.handshake) return false;
    final hs = DtlsHandshakeHeader.parse(rec.fragment);
    if (hs == null) return false;
    if (hs.msgType != v13.TlsV13HandshakeType.clientHello) return false;
    if (hs.fragmentOffset != 0 || hs.fragmentLength != hs.length) {
      // Fragmented ClientHello: assume DTLS 1.3.
      return true;
    }
    final ch = v13.parseClientHello(hs.body);
    if (ch == null) return false;
    final sv = ch.extensionByType(v13.TlsV13ExtensionType.supportedVersions);
    if (sv == null) return false;
    final versions = v13.parseClientHelloSupportedVersionsExtData(sv.data);
    if (versions == null) return false;
    return versions.contains(v13.dtls13Version);
  }

  // ── Record processing ─────────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _processRecord(DtlsRecord record) {
    if (_debug) {
      stderr.writeln(
        '[dtls] record type=${record.contentType} '
        'epoch=${record.epoch} seq=${record.sequenceNumber} '
        'fragLen=${record.fragment.length}',
      );
    }

    // Validate epoch: only 0 (plaintext) and 1 (encrypted) are valid in DTLS 1.2
    if (record.epoch > 1) {
      if (_debug) {
        stderr.writeln(
          '[dtls] dropping record with invalid epoch=${record.epoch}',
        );
      }
      return const Ok(ProcessResult.empty);
    }

    // Decrypt if we have keys and epoch > 0
    Uint8List fragment = record.fragment;
    if (record.epoch > 0) {
      if (_keyBlock == null) {
        // Encrypted record arrived before keys were derived (e.g., Finished
        // arrived before CKE was processed due to reordering). Silently drop
        // and wait for retransmission after keys are established.
        if (_debug) {
          stderr.writeln(
            '[dtls] dropping epoch=${record.epoch} record — no keys yet',
          );
        }
        return const Ok(ProcessResult.empty);
      }
      final decrypted = _decryptRecord(record);
      if (decrypted == null) {
        if (_debug) {
          stderr.writeln(
            '[dtls] decryption failed for epoch=${record.epoch} '
            'seq=${record.sequenceNumber} fragLen=${record.fragment.length}',
          );
        }
        // Decryption failure may be due to key mismatch from reordering.
        // Don't treat as fatal — wait for retransmission.
        return const Ok(ProcessResult.empty);
      }
      fragment = decrypted;
    }

    switch (record.contentType) {
      case DtlsContentType.handshake:
        return _processHandshakeRecord(fragment);
      case DtlsContentType.changeCipherSpec:
        return _processChangeCipherSpec();
      case DtlsContentType.applicationData:
        onApplicationData?.call(fragment);
        return const Ok(ProcessResult.empty);
      case DtlsContentType.alert:
        return _processAlert(fragment);
      default:
        return const Ok(ProcessResult.empty);
    }
  }

  Result<ProcessResult, ProtocolError> _processHandshakeRecord(
    Uint8List fragment,
  ) {
    final hs = DtlsHandshakeHeader.parse(fragment);
    if (hs == null) {
      return Err(const ParseError('DTLS: invalid handshake header'));
    }

    // Duplicate detection (RFC 6347 §4.2.4): skip already-processed messages.
    // ClientHello is exempt because the server must re-process retransmitted
    // ClientHellos to resend the last flight (see _handleClientHello).
    final dupKey = (hs.msgType << 16) | hs.messageSeq;
    if (hs.msgType != DtlsHandshakeType.clientHello &&
        _processedHandshake.contains(dupKey)) {
      if (_debug) {
        stderr.writeln(
          '[dtls] dropping duplicate handshake msgType=${hs.msgType} '
          'msgSeq=${hs.messageSeq}',
        );
      }
      // RFC 6347 §4.2.4: When a duplicate of the last flight's trigger
      // message is received, resend the last flight. This handles the case
      // where the final flight (e.g., server Finished) was lost.
      if (hs.msgType == DtlsHandshakeType.finished &&
          _state == DtlsHandshakeState.connected &&
          _lastFlight != null) {
        if (_debug) {
          stderr.writeln('[dtls] resending last flight for dropped Finished');
        }
        final packets = _lastFlight!
            .map((f) => OutputPacket(
                  data: f,
                  remoteIp: _remoteIp,
                  remotePort: _remotePort,
                ))
            .toList();
        return Ok(ProcessResult(outputPackets: packets));
      }
      return const Ok(ProcessResult.empty);
    }

    // Fragment reassembly: if this is a fragment, buffer it
    Uint8List body;
    Uint8List fullFrag;
    if (hs.fragmentLength < hs.length) {
      final key = (hs.msgType << 16) | hs.messageSeq;
      final assembler = _fragmentBuffer.putIfAbsent(
        key,
        () => _FragmentAssembler(hs.msgType, hs.messageSeq, hs.length),
      );
      assembler.addFragment(hs.fragmentOffset, hs.body);
      if (!assembler.isComplete) return const Ok(ProcessResult.empty);
      final fullBody = assembler.assemble();
      _fragmentBuffer.remove(key);
      final fullHs = DtlsHandshakeHeader(
        msgType: hs.msgType,
        length: hs.length,
        messageSeq: hs.messageSeq,
        fragmentOffset: 0,
        fragmentLength: hs.length,
        body: fullBody,
      );
      body = fullBody;
      fullFrag = fullHs.encode();
    } else {
      body = hs.body;
      fullFrag = fragment;
    }

    // ClientHello is exempt from ordering — the HVR exchange resends it
    // with the same msgSeq=0, and the server's _handleClientHello handles
    // both initial and retransmitted ClientHellos.
    if (hs.msgType == DtlsHandshakeType.clientHello) {
      return _dispatchHandshake(hs.msgType, body, fullFrag);
    }

    // In-order processing (RFC 6347 §4.1.1.1): buffer out-of-order messages
    // and dispatch in message sequence order.
    if (hs.messageSeq == _nextExpectedMsgSeq) {
      // In order — dispatch this and any buffered successors.
      return _dispatchInOrder(hs.msgType, body, fullFrag);
    } else if (hs.messageSeq > _nextExpectedMsgSeq) {
      // Ahead of order — buffer for later.
      if (_debug) {
        stderr.writeln(
          '[dtls] buffering out-of-order msgType=${hs.msgType} '
          'msgSeq=${hs.messageSeq} (expected=$_nextExpectedMsgSeq)',
        );
      }
      _reorderBuffer[hs.messageSeq] = (hs.msgType, body, fullFrag);
      return const Ok(ProcessResult.empty);
    } else {
      // Behind expected — already processed or stale retransmit.
      return const Ok(ProcessResult.empty);
    }
  }

  /// Dispatch the given message and any buffered successors in order.
  Result<ProcessResult, ProtocolError> _dispatchInOrder(
    int msgType,
    Uint8List body,
    Uint8List fullFragment,
  ) {
    final allPackets = <OutputPacket>[];
    Timeout? lastTimeout;

    // Dispatch current message.
    final seqBefore = _nextExpectedMsgSeq;
    final result = _dispatchHandshake(msgType, body, fullFragment);
    if (result.isErr) return result;
    allPackets.addAll(result.value.outputPackets);
    lastTimeout = result.value.nextTimeout ?? lastTimeout;
    // Only auto-increment if the handler didn't reset the counter
    // (e.g., ClientHello processing resets state for a new flight).
    if (_nextExpectedMsgSeq == seqBefore) {
      _nextExpectedMsgSeq++;
    }

    // Flush any buffered successors that are now in order.
    while (_reorderBuffer.containsKey(_nextExpectedMsgSeq)) {
      final (bMsgType, bBody, bFrag) =
          _reorderBuffer.remove(_nextExpectedMsgSeq)!;
      // Skip if already processed (e.g., by a retransmission).
      final dupKey = (bMsgType << 16) | _nextExpectedMsgSeq;
      if (_processedHandshake.contains(dupKey)) {
        _nextExpectedMsgSeq++;
        continue;
      }
      final r = _dispatchHandshake(bMsgType, bBody, bFrag);
      if (r.isErr) return r;
      allPackets.addAll(r.value.outputPackets);
      lastTimeout = r.value.nextTimeout ?? lastTimeout;
      _nextExpectedMsgSeq++;
    }

    return Ok(ProcessResult(outputPackets: allPackets, nextTimeout: lastTimeout));
  }

  Result<ProcessResult, ProtocolError> _dispatchHandshake(
    int msgType,
    Uint8List body,
    Uint8List fullFragment,
  ) {
    if (_debug) {
      stderr.writeln(
        '[dtls] handshake msgType=$msgType bodyLen=${body.length}',
      );
    }
    final key = fullFragment.length >= 6
        ? (msgType << 16) | ((fullFragment[4] << 8) | fullFragment[5])
        : -1;

    // HelloVerifyRequest, Finished, and CertificateVerify are NOT added to
    // transcript here.
    // HVR: RFC 6347 §4.2.1 — excluded from transcript.
    // Finished: must verify against transcript hash BEFORE adding itself.
    // CertificateVerify: signature is over the transcript hash *before* CV
    // is folded in (RFC 5246 §7.4.8); the handler adds it on success.
    if (msgType != DtlsHandshakeType.helloVerifyRequest &&
        msgType != DtlsHandshakeType.finished &&
        !(role == DtlsRole.server &&
            msgType == DtlsHandshakeType.certificateVerify)) {
      // Only add to transcript once (tracked by _receivedHandshake).
      if (!_receivedHandshake.contains(key)) {
        _receivedHandshake.add(key);
        _transcript.add(fullFragment);
      }
    }

    final result = switch (msgType) {
      DtlsHandshakeType.helloVerifyRequest => _handleHelloVerifyRequest(body),
      DtlsHandshakeType.serverHello => _handleServerHello(body),
      DtlsHandshakeType.certificate => _handleCertificate(body),
      DtlsHandshakeType.serverKeyExchange => _handleServerKeyExchange(body),
      DtlsHandshakeType.serverHelloDone => _handleServerHelloDone(),
      DtlsHandshakeType.finished when role == DtlsRole.server =>
        _handleClientFinished(body, fullFragment),
      DtlsHandshakeType.finished => _handleServerFinished(body, fullFragment),
      DtlsHandshakeType.clientHello when role == DtlsRole.server =>
        _handleClientHello(body, fullFragment),
      DtlsHandshakeType.clientKeyExchange when role == DtlsRole.server =>
        _handleClientKeyExchange(body),
      DtlsHandshakeType.certificateVerify when role == DtlsRole.server =>
        _handleCertificateVerify(body, fullFragment),
      _ => const Ok<ProcessResult, ProtocolError>(ProcessResult.empty),
    };

    // Mark as processed only on success — failed messages can be retried
    // when the complete flight is retransmitted (RFC 6347 §4.2.4).
    if (result.isOk) {
      _processedHandshake.add(key);
    }

    return result;
  }

  // ── Client-side handlers ──────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _handleHelloVerifyRequest(
    Uint8List body,
  ) {
    // Extract cookie (body: version(2) || cookie_len(1) || cookie)
    if (body.length < 3) {
      return Err(const ParseError('DTLS: bad HelloVerifyRequest'));
    }
    final cookieLen = body[2];
    if (body.length < 3 + cookieLen) {
      return Err(const ParseError('DTLS: truncated cookie'));
    }
    _cookie = body.sublist(3, 3 + cookieLen);
    return _sendClientHello();
  }

  Result<ProcessResult, ProtocolError> _handleServerHello(Uint8List body) {
    if (body.length < 38) return Err(const ParseError('DTLS: bad ServerHello'));
    _serverRandom = body.sublist(2, 34);
    final sessionIdLen = body[34];
    _sessionId = body.sublist(35, 35 + sessionIdLen);

    var offset = 35 + sessionIdLen;
    if (body.length < offset + 2) return const Ok(ProcessResult.empty);
    final major = body[offset];
    final minor = body[offset + 1];
    if (major == CipherSuite.ecdhEcdsaAes128GcmSha256.major &&
        minor == CipherSuite.ecdhEcdsaAes128GcmSha256.minor) {
      _negotiatedSuite = CipherSuite.ecdhEcdsaAes128GcmSha256;
    }
    offset += 2;

    // Skip compression method (1 byte)
    if (offset < body.length) offset += 1;

    // Parse extensions
    if (offset + 2 <= body.length) {
      final extTotalLen = (body[offset] << 8) | body[offset + 1];
      offset += 2;
      final extEnd = (offset + extTotalLen).clamp(0, body.length);
      while (offset + 4 <= extEnd) {
        final extType = (body[offset] << 8) | body[offset + 1];
        final extLen = (body[offset + 2] << 8) | body[offset + 3];
        offset += 4;
        if (extType == 0x000E && extLen >= 3 && offset + extLen <= extEnd) {
          // use_srtp: 2-byte profile list length + profiles + mki_length
          final profileId = (body[offset + 2] << 8) | body[offset + 3];
          _selectedSrtpProfile = [(profileId >> 8) & 0xFF, profileId & 0xFF];
          if (_debug) {
            stderr.writeln(
              '[dtls] ServerHello use_srtp profile: '
              '0x${profileId.toRadixString(16).padLeft(4, "0")}',
            );
          }
        }
        offset += extLen;
      }
    }

    _state = DtlsHandshakeState.sentClientHelloWithCookie;
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleCertificate(Uint8List body) {
    // Minimal: extract public key bytes from first certificate DER
    // body: 3-byte list length, then 3-byte cert length + DER bytes
    if (body.length < 6) { return Err(const ParseError('DTLS: bad Certificate')); }
    final certLen = (body[3] << 16) | (body[4] << 8) | body[5];
    if (body.length < 6 + certLen) {
      return Err(const ParseError('DTLS: truncated certificate'));
    }
    final certDer = body.sublist(6, 6 + certLen);

    // Defense-in-depth: reject if no expected fingerprint was set (RFC 8827 §5).
    if (expectedRemoteFingerprint == null) {
      return Err(const CryptoError('DTLS: no expected fingerprint set'));
    }
    // Verify fingerprint matches the remote certificate.
    final fp = Sha256.hash(
      certDer,
    ).map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase()).join(':');
    if (fp != expectedRemoteFingerprint) {
      return Err(const CryptoError('DTLS: fingerprint mismatch'));
    }

    // Extract EC public key from SubjectPublicKeyInfo in DER
    _peerPublicKeyBytes = _extractEcPublicKey(certDer);
    _peerCertPubKey = extractEcdsaP256PublicKey(certDer);
    if (_peerCertPubKey == null) {
      return Err(const CryptoError('DTLS: peer cert is not P-256 ecPublicKey'));
    }
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleServerKeyExchange(
    Uint8List body,
  ) {
    // body: ECParameters(3) || ECPoint length(1) || ECPoint(N) ||
    //       SignatureAndHashAlgorithm(2) || signature_length(2) ||
    //       signature(...)
    if (body.length < 5) {
      return Err(const ParseError('DTLS: bad ServerKeyExchange'));
    }
    final pointLen = body[3];
    final paramsEnd = 4 + pointLen;
    if (body.length < paramsEnd + 4) {
      return Err(const ParseError('DTLS: truncated ServerKeyExchange'));
    }
    _peerPublicKeyBytes = body.sublist(4, paramsEnd);

    final sigAlgHash = body[paramsEnd];
    final sigAlgSig = body[paramsEnd + 1];
    final sigLen = (body[paramsEnd + 2] << 8) | body[paramsEnd + 3];
    if (body.length < paramsEnd + 4 + sigLen) {
      return Err(const ParseError('DTLS: SKE signature truncated'));
    }
    if (sigAlgHash != 0x04 || sigAlgSig != 0x03) {
      return Err(const CryptoError(
          'DTLS 1.2: SKE signature scheme is not ECDSA-SHA256'));
    }
    final signature = body.sublist(paramsEnd + 4, paramsEnd + 4 + sigLen);

    final peerPub = _peerCertPubKey;
    if (peerPub == null) {
      return Err(const StateError(
          'DTLS 1.2: SKE arrived before Certificate'));
    }

    // Bytes signed = client_random || server_random || ec_params, where
    // ec_params = curve_type(1) || named_curve(2) || ECPoint(1+N).
    final ecParams = body.sublist(0, paramsEnd);
    final serverRandom = _serverRandom;
    if (serverRandom == null) {
      return Err(const StateError(
          'DTLS 1.2: SKE arrived before ServerHello'));
    }
    final signed = Uint8List(
        _clientRandom.length + serverRandom.length + ecParams.length);
    signed.setRange(0, _clientRandom.length, _clientRandom);
    signed.setRange(_clientRandom.length,
        _clientRandom.length + serverRandom.length, serverRandom);
    signed.setRange(
        _clientRandom.length + serverRandom.length, signed.length, ecParams);

    final ok = EcdsaVerify.verifyP256Sha256(
      publicKey: peerPub,
      message: signed,
      signature: signature,
    );
    if (!ok) {
      return Err(const CryptoError(
          'DTLS 1.2: ServerKeyExchange signature verification failed'));
    }
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleServerHelloDone() {
    if (_peerPublicKeyBytes == null) {
      // ServerKeyExchange hasn't arrived yet (dropped in transit).
      // Return Err so this message is not marked as processed and can
      // be retried when the retransmitted flight delivers the missing SKE.
      return Err(const StateError('DTLS: no server public key'));
    }
    _ecdhKeyPair ??= EcdhKeyPair.generate();
    // If client flight was already sent, resend it (retransmission scenario
    // where SHD arrives again after the missing message was filled in).
    if (_state == DtlsHandshakeState.sentFinished && _lastFlight != null) {
      final packets = _lastFlight!
          .map((f) => OutputPacket(
                data: f,
                remoteIp: _remoteIp,
                remotePort: _remotePort,
              ))
          .toList();
      return Ok(ProcessResult(outputPackets: packets));
    }
    return _sendClientFlight();
  }

  Result<ProcessResult, ProtocolError> _sendClientFlight() {
    final packets = <OutputPacket>[];
    final flight = <Uint8List>[];

    // Certificate
    final certMsg = DtlsHandshakeBuilder.buildCertificate(
      certDer: localCert.derBytes,
      msgSeq: _msgSeqCounter++,
    );
    _transcript.add(certMsg);
    flight.add(_wrapHandshake(certMsg));

    // ClientKeyExchange
    final ckeMsg = DtlsHandshakeBuilder.buildClientKeyExchange(
      publicKeyBytes: _ecdhKeyPair!.publicKeyBytes,
      msgSeq: _msgSeqCounter++,
    );
    _transcript.add(ckeMsg);
    flight.add(_wrapHandshake(ckeMsg));

    // Compute master secret AFTER CKE is in transcript (RFC 7627: session_hash
    // includes all handshake messages up to and including ClientKeyExchange).
    final premaster = _ecdhKeyPair!.computeSharedSecret(_peerPublicKeyBytes!);
    _masterSecret = DtlsKeyMaterial.computeExtendedMasterSecret(
      premasterSecret: premaster,
      sessionHash: _transcript.hash,
    );
    _keyBlock = DtlsKeyBlock.derive(
      masterSecret: _masterSecret!,
      clientRandom: _clientRandom,
      serverRandom: _serverRandom!,
      suite: _negotiatedSuite,
    );

    // CertificateVerify — sign the transcript hash (already SHA-256)
    final transcriptHash = _transcript.hash;
    final signature = localCert.signDigest(transcriptHash);
    final cvMsg = DtlsHandshakeBuilder.buildCertificateVerify(
      signature: signature,
      msgSeq: _msgSeqCounter++,
    );
    _transcript.add(cvMsg);
    flight.add(_wrapHandshake(cvMsg));

    // ChangeCipherSpec (not a handshake message)
    final ccs = DtlsHandshakeBuilder.buildChangeCipherSpec();
    flight.add(_wrapRecord(DtlsContentType.changeCipherSpec, ccs));
    _sendEpoch = 1;
    _sendSeq = 0;

    // Finished
    final verifyData = DtlsKeyMaterial.computeFinishedVerifyData(
      masterSecret: _masterSecret!,
      handshakeHash: _transcript.hash,
      isClient: role == DtlsRole.client,
    );
    final finMsg = DtlsHandshakeBuilder.buildFinished(
      verifyData: verifyData,
      msgSeq: _msgSeqCounter++,
    );
    _transcript.add(finMsg);
    // Finished is encrypted
    final encFinished = _encryptRecord(DtlsContentType.handshake, finMsg);
    flight.add(encFinished);

    for (final f in flight) {
      packets.add(
        OutputPacket(data: f, remoteIp: _remoteIp, remotePort: _remotePort),
      );
    }
    _lastFlight = flight;
    _retransmitCount = 0;
    _state = DtlsHandshakeState.sentFinished;

    final timeout = Timeout(
      at: DateTime.now().add(const Duration(milliseconds: 500)),
      token: DtlsRetransmitToken(_sendEpoch),
    );
    return Ok(ProcessResult(outputPackets: packets, nextTimeout: timeout));
  }

  Result<ProcessResult, ProtocolError> _handleServerFinished(
    Uint8List body,
    Uint8List fullFragment,
  ) {
    // Verify server Finished — hash must NOT include the Finished message itself
    final expectedVerifyData = DtlsKeyMaterial.computeFinishedVerifyData(
      masterSecret: _masterSecret!,
      handshakeHash: _transcript.hash,
      isClient: false,
    );
    if (body.length < 12) return Err(const ParseError('DTLS: short Finished'));
    var mismatch = 0;
    for (var i = 0; i < 12; i++) {
      mismatch |= body[i] ^ expectedVerifyData[i];
    }
    if (mismatch != 0) {
      return Err(const CryptoError('DTLS: Finished verify_data mismatch'));
    }

    // Add server's Finished to transcript
    _transcript.add(fullFragment);
    _state = DtlsHandshakeState.connected;

    // Export SRTP key material — length depends on the profile picked
    // from the server's use_srtp echo (RFC 7714 §12).
    final srtpKeyMaterial = DtlsKeyMaterial.exportSrtpKeyMaterial(
      masterSecret: _masterSecret!,
      clientRandom: _clientRandom,
      serverRandom: _serverRandom!,
      length: _srtpExportLengthForSelectedProfile(),
    );
    // IMPORTANT: key material must never be logged
    onConnected?.call(srtpKeyMaterial);

    return const Ok(ProcessResult.empty);
  }

  /// Bytes of TLS-exported keying material the negotiated SRTP profile
  /// expects. RFC 5764 §4.2 / RFC 7714 §12. Defaults to the legacy
  /// 60-byte AES-CM length when no use_srtp profile is in scope, which
  /// keeps non-SRTP code paths and unit tests working unchanged.
  int _srtpExportLengthForSelectedProfile() {
    final p = _selectedSrtpProfile;
    if (p == null || p.length < 2) return 60;
    final id = (p[0] << 8) | p[1];
    switch (id) {
      case 0x0001: // SRTP_AES128_CM_HMAC_SHA1_80
      case 0x0002: // SRTP_AES128_CM_HMAC_SHA1_32
        return 60;
      case 0x0007: // SRTP_AEAD_AES_128_GCM
        return 56;
      case 0x0008: // SRTP_AEAD_AES_256_GCM
        return 88;
      default:
        return 60;
    }
  }

  // ── Server-side handlers ─────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _handleClientHello(
    Uint8List body,
    Uint8List fullFragment,
  ) {
    if (body.length < 35) return Err(const ParseError('DTLS: bad ClientHello'));
    _clientRandom = body.sublist(2, 34);

    // Parse session_id and cookie from ClientHello body
    final sessionIdLen = body[34];
    final cookieOffset = 35 + sessionIdLen;
    if (cookieOffset >= body.length) {
      return Err(const ParseError('DTLS: truncated ClientHello'));
    }
    final cookieLen = body[cookieOffset];

    if (cookieLen == 0 || _cookie == null) {
      // First ClientHello (no cookie) — send HelloVerifyRequest
      // Remove this ClientHello from transcript (added by caller)
      _transcript.removeLast();
      _cookie = Csprng.randomBytes(16);
      return _sendHelloVerifyRequest(_cookie!);
    }

    // Verify cookie
    if (cookieOffset + 1 + cookieLen > body.length) {
      return Err(const ParseError('DTLS: truncated ClientHello cookie'));
    }
    final receivedCookie = body.sublist(
      cookieOffset + 1,
      cookieOffset + 1 + cookieLen,
    );
    if (receivedCookie.length != _cookie!.length) {
      _transcript.removeLast();
      _cookie = Csprng.randomBytes(16);
      return _sendHelloVerifyRequest(_cookie!);
    }
    var match = true;
    for (var i = 0; i < receivedCookie.length; i++) {
      if (receivedCookie[i] != _cookie![i]) {
        match = false;
        break;
      }
    }
    if (!match) {
      _transcript.removeLast();
      _cookie = Csprng.randomBytes(16);
      return _sendHelloVerifyRequest(_cookie!);
    }

    // Cookie matches — if we've already sent the server flight, this is
    // a retransmission.  Retransmit the last flight instead of regenerating
    // keys (which would desynchronize the master secret).
    if (_serverRandom != null && _lastFlight != null) {
      if (_debug) {
        stderr.writeln(
          '[dtls] ClientHello retransmission — resending last flight',
        );
      }
      final packets = <OutputPacket>[];
      for (final f in _lastFlight!) {
        packets.add(
          OutputPacket(data: f, remoteIp: _remoteIp, remotePort: _remotePort),
        );
      }
      return Ok(ProcessResult(outputPackets: packets));
    }

    // Clear old transcript, keep only this ClientHello
    // (RFC 6347 §4.2.1: first ClientHello and HVR not in transcript)
    _transcript.clear();
    _receivedHandshake.clear();
    _processedHandshake.clear();
    _reorderBuffer.clear();
    // Expect the next client message after this ClientHello's msgSeq.
    // Chrome increments msgSeq for the cookie-bearing ClientHello (msgSeq=1),
    // so the next message (Certificate/ClientKeyExchange) is at msgSeq=2.
    final chMsgSeq = (fullFragment[4] << 8) | fullFragment[5];
    _nextExpectedMsgSeq = chMsgSeq + 1;
    _transcript.add(fullFragment);
    // Mark ClientHello as received so retransmissions don't re-add to transcript.
    _receivedHandshake.add(
      (DtlsHandshakeType.clientHello << 16) | chMsgSeq,
    );

    // Parse extensions from ClientHello to find use_srtp profile
    _parseSrtpExtension(body, cookieOffset + 1 + cookieLen);

    // Parse and log cipher suites from ClientHello
    if (_debug) {
      _logClientHelloCipherSuites(body, cookieOffset + 1 + cookieLen);
    }

    // Proceed to send server flight
    return _sendServerFlight();
  }

  /// Selected SRTP profile from client's use_srtp extension (null if not present)
  List<int>? _selectedSrtpProfile;

  /// The negotiated SRTP profile ID (0x0001 = AES_CM_128_HMAC_SHA1_80).
  /// Forwards to the inner v1.3 state machine when DTLS 1.3 was selected.
  int? get selectedSrtpProfileId {
    final v13Inner = _v13Inner;
    if (v13Inner != null) return v13Inner.selectedSrtpProfileId;
    return _selectedSrtpProfile != null
        ? (_selectedSrtpProfile![0] << 8) | _selectedSrtpProfile![1]
        : null;
  }

  void _logClientHelloCipherSuites(Uint8List body, int afterCookie) {
    if (afterCookie + 2 > body.length) return;
    final suitesLen = (body[afterCookie] << 8) | body[afterCookie + 1];
    final suitesStart = afterCookie + 2;
    final suites = <String>[];
    for (var i = 0; i < suitesLen; i += 2) {
      if (suitesStart + i + 1 < body.length) {
        suites.add(
          '0x${body[suitesStart + i].toRadixString(16).padLeft(2, "0")}'
          '${body[suitesStart + i + 1].toRadixString(16).padLeft(2, "0")}',
        );
      }
    }
    stderr.writeln(
      '[dtls] ClientHello cipher suites (${suites.length}): ${suites.join(", ")}',
    );
    // Also log the msgSeq we'll use for server flight
    stderr.writeln(
      '[dtls] Server flight will use msgSeqCounter=$_msgSeqCounter',
    );
  }

  void _parseSrtpExtension(Uint8List body, int afterCookie) {
    _selectedSrtpProfile = null;
    if (afterCookie >= body.length) return;
    // cipher_suites: 2 byte length + suites
    final suitesLen = (body[afterCookie] << 8) | body[afterCookie + 1];
    var off = afterCookie + 2 + suitesLen;
    if (off >= body.length) return;
    // compression_methods: 1 byte length + methods
    final compLen = body[off];
    off += 1 + compLen;
    if (off + 2 > body.length) return;
    // extensions_length
    final extLen = (body[off] << 8) | body[off + 1];
    off += 2;
    final extEnd = off + extLen;
    while (off + 4 <= extEnd && off + 4 <= body.length) {
      final extType = (body[off] << 8) | body[off + 1];
      final extDataLen = (body[off + 2] << 8) | body[off + 3];
      off += 4;
      if (extType == 0x000E &&
          extDataLen >= 4 &&
          off + extDataLen <= body.length) {
        // use_srtp: pick first supported profile
        final profilesLen = (body[off] << 8) | body[off + 1];
        if (_debug) {
          final profiles = <int>[];
          for (var j = 0; j < profilesLen; j += 2) {
            profiles.add((body[off + 2 + j] << 8) | body[off + 2 + j + 1]);
          }
          stderr.writeln(
            '[dtls] use_srtp profiles offered: ${profiles.map((p) => "0x${p.toRadixString(16).padLeft(4, "0")}").join(", ")}',
          );
        }
        // Prefer SRTP_AES128_CM_HMAC_SHA1_80 (0x0001) when the client offers
        // it, falling back to AEAD_AES_128_GCM (0x0007). Both Chrome and
        // Firefox advertise 0x0001, so this picks the common-denominator
        // profile and avoids known webdartc AES-GCM key-derivation issues
        // (RFC 7714 §11 — 12-byte master salt, not 14).
        int? picked;
        for (var i = 0; i < profilesLen; i += 2) {
          final profileId = (body[off + 2 + i] << 8) | body[off + 2 + i + 1];
          if (profileId == 0x0001) {
            picked = 0x0001;
            break;
          }
        }
        if (picked == null) {
          for (var i = 0; i < profilesLen; i += 2) {
            final profileId = (body[off + 2 + i] << 8) | body[off + 2 + i + 1];
            if (profileId == 0x0007) {
              picked = 0x0007;
              break;
            }
          }
        }
        if (picked != null) {
          _selectedSrtpProfile = [(picked >> 8) & 0xFF, picked & 0xFF];
          if (_debug) {
            stderr.writeln(
              '[dtls] selected SRTP profile: 0x${picked.toRadixString(16).padLeft(4, "0")}',
            );
          }
        }
      }
      off += extDataLen;
    }
  }

  Result<ProcessResult, ProtocolError> _sendHelloVerifyRequest(
    Uint8List cookie,
  ) {
    final body = Uint8List(3 + cookie.length);
    body[0] = 0xFE; // DTLS 1.2
    body[1] = 0xFD;
    body[2] = cookie.length;
    body.setRange(3, body.length, cookie);
    final hs = DtlsHandshakeHeader(
      msgType: DtlsHandshakeType.helloVerifyRequest,
      length: body.length,
      messageSeq: 0,
      fragmentOffset: 0,
      fragmentLength: body.length,
      body: body,
    );
    final hsBytes = hs.encode();
    final record = _wrapHandshake(hsBytes);
    return Ok(
      ProcessResult(
        outputPackets: [
          OutputPacket(
            data: record,
            remoteIp: _remoteIp,
            remotePort: _remotePort,
          ),
        ],
      ),
    );
  }

  Result<ProcessResult, ProtocolError> _sendServerFlight() {
    _serverRandom = _buildRandom();
    _ecdhKeyPair = EcdhKeyPair.generate();
    // Server msgSeq starts after HVR (msgSeq=0), so ServerHello = 1
    _msgSeqCounter = 1;

    final packets = <OutputPacket>[];
    final flight = <Uint8List>[];

    // ServerHello
    final shMsg = DtlsHandshakeBuilder.buildServerHello(
      random: _serverRandom!,
      sessionId: Uint8List(0),
      suite: _negotiatedSuite,
      msgSeq: _msgSeqCounter++,
      srtpProfile: _selectedSrtpProfile,
    );
    _transcript.add(shMsg);
    flight.add(_wrapHandshake(shMsg));

    // Certificate
    final certMsg = DtlsHandshakeBuilder.buildCertificate(
      certDer: localCert.derBytes,
      msgSeq: _msgSeqCounter++,
    );
    _transcript.add(certMsg);
    flight.add(_wrapHandshake(certMsg));

    // ServerKeyExchange — sign (client_random || server_random || ec_params)
    final ecParams = Uint8List(4 + _ecdhKeyPair!.publicKeyBytes.length);
    ecParams[0] = 0x03; // named_curve
    ecParams[1] = 0x00;
    ecParams[2] = 0x17; // secp256r1
    ecParams[3] = _ecdhKeyPair!.publicKeyBytes.length;
    ecParams.setRange(4, ecParams.length, _ecdhKeyPair!.publicKeyBytes);

    final toSign = Uint8List(
      _clientRandom.length + _serverRandom!.length + ecParams.length,
    );
    toSign.setRange(0, _clientRandom.length, _clientRandom);
    toSign.setRange(
      _clientRandom.length,
      _clientRandom.length + _serverRandom!.length,
      _serverRandom!,
    );
    toSign.setRange(
      _clientRandom.length + _serverRandom!.length,
      toSign.length,
      ecParams,
    );

    // sign() uses kSecKeyAlgorithmECDSASignatureMessageX962SHA256
    // which internally hashes with SHA-256 — do NOT pre-hash
    final signature = localCert.sign(toSign);

    final skeMsg = DtlsHandshakeBuilder.buildServerKeyExchange(
      ecPublicKey: _ecdhKeyPair!.publicKeyBytes,
      signature: signature,
      msgSeq: _msgSeqCounter++,
    );
    _transcript.add(skeMsg);
    flight.add(_wrapHandshake(skeMsg));

    // ServerHelloDone
    final shdMsg = DtlsHandshakeBuilder.buildServerHelloDone(
      msgSeq: _msgSeqCounter++,
    );
    _transcript.add(shdMsg);
    flight.add(_wrapHandshake(shdMsg));

    for (final f in flight) {
      packets.add(
        OutputPacket(data: f, remoteIp: _remoteIp, remotePort: _remotePort),
      );
    }
    _lastFlight = flight;
    _retransmitCount = 0;
    _state = DtlsHandshakeState.sentServerHelloDone;

    final timeout = Timeout(
      at: DateTime.now().add(const Duration(milliseconds: 500)),
      token: DtlsRetransmitToken(0),
    );
    return Ok(ProcessResult(outputPackets: packets, nextTimeout: timeout));
  }

  Result<ProcessResult, ProtocolError> _handleClientKeyExchange(
    Uint8List body,
  ) {
    if (body.isEmpty) {
      return Err(const ParseError('DTLS: empty ClientKeyExchange'));
    }
    final pointLen = body[0];
    if (body.length < 1 + pointLen) {
      return Err(const ParseError('DTLS: truncated ClientKeyExchange'));
    }
    _peerPublicKeyBytes = body.sublist(1, 1 + pointLen);

    // Compute shared secret and derive keys
    if (_ecdhKeyPair == null || _serverRandom == null) {
      return Err(const StateError('DTLS: server state not ready for CKE'));
    }
    final premaster = _ecdhKeyPair!.computeSharedSecret(_peerPublicKeyBytes!);

    // Use extended master secret (RFC 7627)
    _masterSecret = DtlsKeyMaterial.computeExtendedMasterSecret(
      premasterSecret: premaster,
      sessionHash: _transcript.hash,
    );
    _keyBlock = DtlsKeyBlock.derive(
      masterSecret: _masterSecret!,
      clientRandom: _clientRandom,
      serverRandom: _serverRandom!,
      suite: _negotiatedSuite,
    );
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleCertificateVerify(
    Uint8List body,
    Uint8List fullFragment,
  ) {
    // RFC 5246 §7.4.8: SignatureAndHashAlgorithm(2) || signature_length(2)
    //                  || signature(...)
    if (body.length < 4) {
      return Err(const ParseError('DTLS 1.2: short CertificateVerify'));
    }
    final hashAlg = body[0];
    final sigAlg = body[1];
    final sigLen = (body[2] << 8) | body[3];
    if (4 + sigLen != body.length) {
      return Err(const ParseError('DTLS 1.2: bad CertificateVerify'));
    }
    if (hashAlg != 0x04 || sigAlg != 0x03) {
      return Err(const CryptoError(
          'DTLS 1.2: client CertificateVerify is not ECDSA-SHA256'));
    }
    final signature = body.sublist(4, 4 + sigLen);

    final peerPub = _peerCertPubKey;
    if (peerPub == null) {
      return Err(const StateError(
          'DTLS 1.2: CertificateVerify before client Certificate'));
    }

    // Transcript at this point excludes the CV message itself (the dispatcher
    // skips folding CV in until verification succeeds). The bytes signed by
    // the client are the transcript bytes; verifyP256Sha256 hashes internally.
    final ok = EcdsaVerify.verifyP256Sha256(
      publicKey: peerPub,
      message: _transcript.bytes,
      signature: signature,
    );
    if (!ok) {
      return Err(const CryptoError(
          'DTLS 1.2: client CertificateVerify failed'));
    }
    _transcript.add(fullFragment);
    final key = fullFragment.length >= 6
        ? (DtlsHandshakeType.certificateVerify << 16) |
            ((fullFragment[4] << 8) | fullFragment[5])
        : -1;
    _receivedHandshake.add(key);
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleClientFinished(
    Uint8List body,
    Uint8List fullFragment,
  ) {
    if (_masterSecret == null) {
      return Err(const StateError('DTLS: no master secret for Finished'));
    }
    // Verify client Finished — hash must NOT include the Finished message itself
    final expectedVerifyData = DtlsKeyMaterial.computeFinishedVerifyData(
      masterSecret: _masterSecret!,
      handshakeHash: _transcript.hash,
      isClient: true, // verifying CLIENT's Finished
    );
    if (body.length < 12) return Err(const ParseError('DTLS: short Finished'));
    var mismatch = 0;
    for (var i = 0; i < 12; i++) {
      mismatch |= body[i] ^ expectedVerifyData[i];
    }
    if (mismatch != 0) {
      return Err(const CryptoError('DTLS: Finished verify_data mismatch'));
    }

    // Add client's Finished to transcript (needed for server Finished hash)
    _transcript.add(fullFragment);

    // Send server ChangeCipherSpec + Finished
    return _sendServerFinishedFlight();
  }

  Result<ProcessResult, ProtocolError> _sendServerFinishedFlight() {
    final packets = <OutputPacket>[];
    final flight = <Uint8List>[];

    // ChangeCipherSpec
    final ccs = DtlsHandshakeBuilder.buildChangeCipherSpec();
    flight.add(_wrapRecord(DtlsContentType.changeCipherSpec, ccs));
    _sendEpoch = 1;
    _sendSeq = 0;

    // Finished
    final verifyData = DtlsKeyMaterial.computeFinishedVerifyData(
      masterSecret: _masterSecret!,
      handshakeHash: _transcript.hash,
      isClient: false, // server's Finished
    );
    final finMsg = DtlsHandshakeBuilder.buildFinished(
      verifyData: verifyData,
      msgSeq: _msgSeqCounter++,
    );
    _transcript.add(finMsg);
    final encFinished = _encryptRecord(DtlsContentType.handshake, finMsg);
    flight.add(encFinished);

    for (final f in flight) {
      packets.add(
        OutputPacket(data: f, remoteIp: _remoteIp, remotePort: _remotePort),
      );
    }
    _lastFlight = flight;
    _state = DtlsHandshakeState.connected;

    // Export SRTP key material — length depends on the profile picked
    // from the client's use_srtp offer (RFC 7714 §12).
    final srtpKeyMaterial = DtlsKeyMaterial.exportSrtpKeyMaterial(
      masterSecret: _masterSecret!,
      clientRandom: _clientRandom,
      serverRandom: _serverRandom!,
      length: _srtpExportLengthForSelectedProfile(),
    );
    onConnected?.call(srtpKeyMaterial);

    return Ok(ProcessResult(outputPackets: packets));
  }

  // ── Common builders ───────────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _sendClientHello() {
    _clientRandom = _buildRandom();
    _msgSeqCounter = 1; // after clienthello

    // RFC 6347 §4.2.1: The initial ClientHello and HelloVerifyRequest MUST NOT
    // be included in the handshake transcript. Clear any previous ClientHello
    // so only the current one (with cookie, if retransmitting) is in the hash.
    _transcript.clear();
    _receivedHandshake.clear();
    _processedHandshake.clear();
    _reorderBuffer.clear();
    if (_cookie != null) {
      // After HVR exchange, next expected incoming msgSeq from server is 1
      // (ServerHello). ClientHello(0) and HVR(0) are excluded from transcript.
      _nextExpectedMsgSeq = 1;
    } else {
      // Initial ClientHello — expect HVR at msgSeq=0.
      _nextExpectedMsgSeq = 0;
    }

    final hs = DtlsHandshakeBuilder.buildClientHello(
      random: _clientRandom,
      sessionId: _sessionId ?? Uint8List(0),
      cookie: _cookie,
      suites: [CipherSuite.ecdhEcdsaAes128GcmSha256],
    );
    _transcript.add(hs);

    final record = _wrapHandshake(hs);
    _lastFlight = [record];
    _retransmitCount = 0;
    _state = _cookie != null
        ? DtlsHandshakeState.sentClientHelloWithCookie
        : DtlsHandshakeState.sentClientHello;

    final timeout = Timeout(
      at: DateTime.now().add(const Duration(milliseconds: 500)),
      token: DtlsRetransmitToken(0),
    );
    return Ok(
      ProcessResult(
        outputPackets: [
          OutputPacket(
            data: record,
            remoteIp: _remoteIp,
            remotePort: _remotePort,
          ),
        ],
        nextTimeout: timeout,
      ),
    );
  }

  // ── Retransmit ────────────────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _retransmit(int epoch) {
    if (_state == DtlsHandshakeState.connected) {
      return const Ok(ProcessResult.empty);
    }
    if (_retransmitCount >= _maxRetransmit) {
      _state = DtlsHandshakeState.failed;
      return Err(const StateError('DTLS: max retransmissions exceeded'));
    }
    _retransmitCount++;

    final last = _lastFlight;
    if (last == null) return const Ok(ProcessResult.empty);

    final packets = last
        .map(
          (f) => OutputPacket(
            data: f,
            remoteIp: _remoteIp,
            remotePort: _remotePort,
          ),
        )
        .toList();

    // Exponential backoff: 500ms * 2^count, capped at 60s
    final delayMs = (500 * (1 << _retransmitCount)).clamp(0, 60000);
    final timeout = Timeout(
      at: DateTime.now().add(Duration(milliseconds: delayMs)),
      token: DtlsRetransmitToken(epoch),
    );
    return Ok(ProcessResult(outputPackets: packets, nextTimeout: timeout));
  }

  // ── Record encryption/decryption ──────────────────────────────────────────

  Uint8List _encryptRecord(int contentType, Uint8List plaintext) {
    final kb = _keyBlock;
    if (kb == null) return _wrapRecord(contentType, plaintext);

    final isClient = role == DtlsRole.client;
    final key = isClient ? kb.clientWriteKey : kb.serverWriteKey;
    final iv = isClient ? kb.clientWriteIv : kb.serverWriteIv;

    final ciphertext = AeadRecord.encrypt(
      key: key,
      implicitIv: iv,
      epoch: _sendEpoch,
      seqNum: _sendSeq,
      contentType: contentType,
      plaintext: plaintext,
    );
    final record = DtlsRecord(
      contentType: contentType,
      version: 0xFEFD,
      epoch: _sendEpoch,
      sequenceNumber: _sendSeq++,
      fragment: ciphertext,
    );
    return record.encode();
  }

  Uint8List? _decryptRecord(DtlsRecord record) {
    final kb = _keyBlock;
    if (kb == null) return null;

    final isClient = role == DtlsRole.client;
    // Receive key: opposite side's write key
    final key = isClient ? kb.serverWriteKey : kb.clientWriteKey;
    final iv = isClient ? kb.serverWriteIv : kb.clientWriteIv;

    return AeadRecord.decrypt(
      key: key,
      implicitIv: iv,
      epoch: record.epoch,
      seqNum: record.sequenceNumber,
      contentType: record.contentType,
      ciphertextWithNonceAndTag: record.fragment,
    );
  }

  Uint8List _wrapHandshake(Uint8List handshakeMsg) =>
      _wrapRecord(DtlsContentType.handshake, handshakeMsg);

  Uint8List _wrapRecord(int contentType, Uint8List fragment) {
    final record = DtlsRecord(
      contentType: contentType,
      version: 0xFEFD,
      epoch: 0,
      sequenceNumber: _sendSeq++,
      fragment: fragment,
    );
    return record.encode();
  }

  Result<ProcessResult, ProtocolError> _processChangeCipherSpec() {
    _recvEpoch = 1;
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _processAlert(Uint8List body) {
    if (body.length >= 2) {
      final level = body[0]; // 1=warning, 2=fatal
      final desc = body[1];
      if (_debug) {
        stderr.writeln(
          '[dtls] ALERT level=$level desc=$desc'
          ' (${_alertName(desc)})',
        );
      }
      if (level == 2) _state = DtlsHandshakeState.failed;
    }
    return const Ok(ProcessResult.empty);
  }

  /// Send a DTLS alert to the remote peer.
  Result<ProcessResult, ProtocolError> sendAlert(int level, int description) {
    final alertBody = Uint8List(2);
    alertBody[0] = level;
    alertBody[1] = description;
    final record = _sendEpoch > 0
        ? _encryptRecord(DtlsContentType.alert, alertBody)
        : _wrapRecord(DtlsContentType.alert, alertBody);
    if (level == 2) _state = DtlsHandshakeState.failed;
    return Ok(
      ProcessResult(
        outputPackets: [
          OutputPacket(
            data: record,
            remoteIp: _remoteIp,
            remotePort: _remotePort,
          ),
        ],
      ),
    );
  }

  static String _alertName(int desc) => switch (desc) {
    0 => 'close_notify',
    10 => 'unexpected_message',
    20 => 'bad_record_mac',
    40 => 'handshake_failure',
    42 => 'bad_certificate',
    43 => 'unsupported_certificate',
    47 => 'illegal_parameter',
    48 => 'unknown_ca',
    50 => 'decode_error',
    51 => 'decrypt_error',
    70 => 'protocol_version',
    71 => 'insufficient_security',
    80 => 'internal_error',
    90 => 'user_canceled',
    _ => 'unknown($desc)',
  };

  // ── Utilities ─────────────────────────────────────────────────────────────

  static Uint8List _buildRandom() {
    // 4-byte Unix time + 28 random bytes (RFC 5246 §7.4.1.2)
    final random = Uint8List(32);
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    random[0] = (now >> 24) & 0xFF;
    random[1] = (now >> 16) & 0xFF;
    random[2] = (now >> 8) & 0xFF;
    random[3] = now & 0xFF;
    final rest = Csprng.randomBytes(28);
    random.setRange(4, 32, rest);
    return random;
  }

  /// Extract EC public key bytes from an X.509 DER certificate.
  static Uint8List? _extractEcPublicKey(Uint8List der) {
    // Minimal DER walk to find BIT STRING containing EC point
    // EC point starts with 0x04 and is 65 bytes for P-256
    for (var i = 0; i < der.length - 65; i++) {
      if (der[i] == 0x04 && (i == 0 || der[i - 1] == 0x00)) {
        // 0x00 is the "unused bits" prefix in BIT STRING
        return der.sublist(i, i + 65);
      }
    }
    return null;
  }
}

/// Reassembles fragmented DTLS handshake messages.
final class _FragmentAssembler {
  final int msgType;
  final int messageSeq;
  final int totalLength;
  final Uint8List _buffer;
  final List<bool> _received;

  _FragmentAssembler(this.msgType, this.messageSeq, this.totalLength)
    : _buffer = Uint8List(totalLength),
      _received = List<bool>.filled(totalLength, false);

  void addFragment(int offset, Uint8List data) {
    if (offset + data.length > totalLength) return;
    _buffer.setRange(offset, offset + data.length, data);
    for (var i = offset; i < offset + data.length; i++) {
      _received[i] = true;
    }
  }

  bool get isComplete => _received.every((r) => r);

  Uint8List assemble() => Uint8List.fromList(_buffer);
}
