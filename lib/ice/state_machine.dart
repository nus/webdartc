import 'dart:typed_data';

import '../core/state_machine.dart';
import '../crypto/csprng.dart';
import '../stun/builder.dart';
import '../stun/message.dart';
import '../stun/parser.dart';
import 'candidate.dart';
import 'candidate_pair.dart';

export 'candidate.dart';
export 'candidate_pair.dart';

/// Parsed STUN server endpoint.
final class StunServer {
  final String host;
  final int port;
  const StunServer({required this.host, required this.port});

  /// Parse a STUN URI (RFC 7064): "stun:host[:port]"
  /// Returns null if the URI is not a valid stun: URI.
  static StunServer? parse(String uri) {
    final u = uri.trim();
    if (!u.startsWith('stun:')) return null;
    final hostPort = u.substring(5);
    final colonIdx = hostPort.lastIndexOf(':');
    if (colonIdx <= 0) {
      // No port — default 3478
      return StunServer(host: hostPort, port: 3478);
    }
    final portStr = hostPort.substring(colonIdx + 1);
    final port = int.tryParse(portStr);
    if (port == null) return null;
    return StunServer(host: hostPort.substring(0, colonIdx), port: port);
  }
}

/// ICE state machine (RFC 8445 + RFC 8840 Trickle ICE).
///
/// Pure state machine — no I/O.
final class IceStateMachine implements ProtocolStateMachine {
  IceState _state = IceState.iceNew;
  IceParameters? _localParams;
  IceParameters? _remoteParams;

  final List<IceCandidate> _localCandidates = [];
  final List<IceCandidate> _remoteCandidates = [];
  final List<CandidatePair> _pairs = [];
  CandidatePair? _selectedPair;

  /// Whether this agent is the controlling agent (offerer).
  bool controlling;

  // Tie-breaker value for ICE role conflict resolution (RFC 8445 §6.1.3.1).
  final int _tieBreaker;

  // Ongoing connectivity checks keyed by transaction ID.
  final Map<String, _PendingCheck> _pendingChecks = {};

  // Pending STUN server gathering requests keyed by transaction ID.
  final Map<String, _StunServerRequest> _stunServerRequests = {};

  // STUN servers to query for srflx candidates.
  final List<StunServer> _stunServers;

  // Timer counter for IceTimerToken IDs.
  int _timerIdCounter = 0;

  // Keepalive interval: 15s (RFC 8445 §11)
  static const Duration _keepaliveInterval = Duration(seconds: 15);

  // Connectivity check retransmit timeout: 500ms base (RFC 8445 §14.3)
  static const Duration _checkTimeout = Duration(milliseconds: 500);

  // STUN server gathering timeout
  static const Duration _stunGatherTimeout = Duration(seconds: 3);

  /// Emitted when a local candidate is gathered.
  void Function(IceCandidate)? onLocalCandidate;

  /// Emitted when the ICE state changes.
  void Function(IceState)? onStateChange;

  /// Emitted when data arrives on the selected pair (non-STUN packet).
  void Function(Uint8List data, String remoteIp, int remotePort)? onData;

  IceStateMachine({
    required this.controlling,
    List<StunServer> stunServers = const [],
  })  : _stunServers = stunServers,
        _tieBreaker = Csprng.randomUint32() << 32 | Csprng.randomUint32();

  IceState get state => _state;
  CandidatePair? get selectedPair => _selectedPair;
  String? get selectedRemoteIp => _selectedPair?.remote.ip;
  int? get selectedRemotePort => _selectedPair?.remote.port;

  // ── Public control API ───────────────────────────────────────────────────

  /// Start ICE gathering with the given local parameters and host candidate.
  ///
  /// [localIp] and [localPort] are the bound UDP address.
  /// Returns a [ProcessResult] — no packets to send at this stage, but the
  /// caller should emit [onLocalCandidate] for the host candidate.
  Result<ProcessResult, ProtocolError> startGathering(
    IceParameters localParams, {
    required String localIp,
    required int localPort,
  }) {
    _localParams = localParams;
    _setState(IceState.iceGathering);

    final foundation = Csprng.randomHex(4);
    final priority = IceCandidate.computePriority(
      typePreference: IceCandidate.typePreferenceHost,
      localPreference: 65535,
      componentId: 1,
    );
    final hostCandidate = IceCandidate(
      foundation: foundation,
      componentId: 1,
      transport: 'udp',
      priority: priority,
      ip: localIp,
      port: localPort,
      type: IceCandidateType.host,
    );
    _localCandidates.add(hostCandidate);
    onLocalCandidate?.call(hostCandidate);

    // Send STUN Binding Requests to STUN servers for srflx candidates.
    if (_stunServers.isNotEmpty) {
      final packets = <OutputPacket>[];
      for (final server in _stunServers) {
        final txId = Csprng.randomBytes(12);
        final msg = StunMessage(
          type: StunMessageType.bindingRequest,
          transactionId: txId,
        );
        final raw = StunMessageBuilder.build(msg);
        packets.add(OutputPacket(data: raw, remoteIp: server.host, remotePort: server.port));
        _stunServerRequests[_txIdString(txId)] = _StunServerRequest(
          server: server,
          sentAt: DateTime.now(),
          localIp: localIp,
          localPort: localPort,
        );
      }
      // Schedule a gathering timeout
      final timeout = Timeout(
        at: DateTime.now().add(_stunGatherTimeout),
        token: IceGatheringTimeoutToken(),
      );
      return Ok(ProcessResult(outputPackets: packets, nextTimeout: timeout));
    }

    _setState(IceState.iceGatheringComplete);
    // If remote params were already set (answerer flow), start checks now.
    if (_remoteParams != null) {
      return Ok(_startChecks());
    }
    return const Ok(ProcessResult.empty);
  }

  /// Add a remote ICE candidate (Trickle ICE).
  ///
  /// Returns a [ProcessResult] that may include an initial STUN check to send.
  Result<ProcessResult, ProtocolError> addRemoteCandidate(
      IceCandidate candidate) {
    _remoteCandidates.add(candidate);
    if (_state == IceState.iceGatheringComplete ||
        _state == IceState.iceChecking ||
        _state == IceState.iceConnected) {
      _pairCandidate(candidate);
      if (_state == IceState.iceChecking) {
        final packets = _doNextCheck();
        if (packets.isNotEmpty) {
          // Schedule a retransmit timer for this check.
          final nextTimeout = Timeout(
            at: DateTime.now().add(_checkTimeout),
            token: IceTimerToken(++_timerIdCounter),
          );
          return Ok(ProcessResult(outputPackets: packets, nextTimeout: nextTimeout));
        }
      }
    }
    return const Ok(ProcessResult.empty);
  }

  /// Set remote ICE parameters (from SDP) and start connectivity checking.
  ///
  /// Returns a [ProcessResult] with the first STUN check packet and a
  /// retransmit timer so the transport can drive ICE checking.
  Result<ProcessResult, ProtocolError> setRemoteParameters(
      IceParameters params) {
    _remoteParams = params;
    if (_state == IceState.iceGatheringComplete) {
      return Ok(_startChecks());
    }
    return const Ok(ProcessResult.empty);
  }

  /// Send application data (non-STUN) on the selected pair.
  Result<ProcessResult, ProtocolError> sendData(Uint8List payload) {
    final pair = _selectedPair;
    if (pair == null) {
      return Err(const StateError('ICE: no selected pair — cannot send data'));
    }
    return Ok(ProcessResult(
      outputPackets: [
        OutputPacket(
          data: payload,
          remoteIp: pair.remote.ip,
          remotePort: pair.remote.port,
        ),
      ],
    ));
  }

  /// Whether [packet] is a STUN packet (for demultiplexing).
  static bool isStunPacket(Uint8List packet) => StunParser.isStun(packet);

  // ── ProtocolStateMachine ─────────────────────────────────────────────────

  @override
  Result<ProcessResult, ProtocolError> processInput(
    Uint8List packet, {
    required String remoteIp,
    required int remotePort,
  }) {
    if (!StunParser.isStun(packet)) {
      // Non-STUN packet delivered on selected pair — pass up.
      onData?.call(packet, remoteIp, remotePort);
      return const Ok(ProcessResult.empty);
    }

    final parseResult = StunParser.parse(packet);
    if (parseResult.isErr) {
      return Err(parseResult.error);
    }
    final msg = parseResult.value;

    if (msg.type == StunMessageType.bindingRequest) {
      return _handleBindingRequest(msg, remoteIp, remotePort, packet);
    } else if (msg.type == StunMessageType.bindingSuccessResponse) {
      // Check if this is a response to a STUN server gathering request.
      final txId = _txIdString(msg.transactionId);
      if (_stunServerRequests.containsKey(txId)) {
        return _handleStunServerResponse(msg, txId);
      }
      return _handleBindingResponse(msg, remoteIp, remotePort);
    } else if (msg.type == StunMessageType.bindingErrorResponse) {
      // Also check STUN server responses.
      final txId = _txIdString(msg.transactionId);
      _stunServerRequests.remove(txId);
      return _handleBindingError(msg);
    }

    return const Ok(ProcessResult.empty);
  }

  @override
  Result<ProcessResult, ProtocolError> handleTimeout(TimerToken token) {
    if (token is IceTimerToken) {
      return _handleIceTimer(token.id);
    }
    if (token is IceKeepaliveToken) {
      return _sendKeepalive();
    }
    if (token is IceGatheringTimeoutToken) {
      return _handleGatheringTimeout();
    }
    return const Ok(ProcessResult.empty);
  }

  // ── STUN message handling ─────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _handleBindingRequest(
    StunMessage msg,
    String remoteIp,
    int remotePort,
    Uint8List rawPacket,
  ) {
    final remoteParams = _remoteParams;
    if (remoteParams == null) {
      // Not ready yet — respond with error 400
      return _buildErrorResponse(msg.transactionId, 400, 'Bad Request', remoteIp, remotePort);
    }

    // Validate USERNAME
    final usernameAttr = msg.attribute<UsernameAttr>();
    if (usernameAttr == null) {
      return _buildErrorResponse(msg.transactionId, 400, 'Bad Request', remoteIp, remotePort);
    }
    final localParams = _localParams!;
    final expectedUsername = '${localParams.usernameFragment}:${remoteParams.usernameFragment}';
    if (usernameAttr.username != expectedUsername) {
      return _buildErrorResponse(msg.transactionId, 401, 'Unauthorized', remoteIp, remotePort);
    }

    // Validate MESSAGE-INTEGRITY
    final integrityAttr = msg.attribute<MessageIntegrityAttr>();
    if (integrityAttr == null) {
      return _buildErrorResponse(msg.transactionId, 400, 'Bad Request', remoteIp, remotePort);
    }

    // Check if NOMINATED (for controlled agent)
    final nominated = msg.attribute<UseCandidateAttr>() != null;

    // Find or create matching pair; may return triggered-check packets (RFC 8445 §7.3.1.4).
    final triggeredPackets = _updatePairFromRequest(remoteIp, remotePort, nominated);

    // Build success response
    final successResult = _buildSuccessResponse(
        msg.transactionId, remoteIp, remotePort, localParams.password);
    if (!successResult.isOk) return successResult;

    final allPackets = [
      ...successResult.value.outputPackets,
      ...triggeredPackets,
    ];
    return Ok(ProcessResult(outputPackets: allPackets));
  }

  Result<ProcessResult, ProtocolError> _handleBindingResponse(
    StunMessage msg,
    String remoteIp,
    int remotePort,
  ) {
    final txId = _txIdString(msg.transactionId);
    final check = _pendingChecks.remove(txId);
    if (check == null) return const Ok(ProcessResult.empty);

    // Mark pair as succeeded
    check.pair.state = CandidatePairState.succeeded;
    check.pair.roundTripTimeMs =
        DateTime.now().difference(check.sentAt).inMilliseconds;

    // Check XOR-MAPPED-ADDRESS for peer-reflexive candidate discovery
    final xma = msg.attribute<XorMappedAddress>();
    if (xma != null && (xma.ip != check.pair.local.ip || xma.port != check.pair.local.port)) {
      // Peer-reflexive candidate discovered — add to local candidates
      _discoverPrflxCandidate(xma.ip, xma.port, check.pair);
    }

    // Nominate if controlling
    if (controlling && check.nominated) {
      check.pair.nominated = true;
      _selectPair(check.pair);
    } else if (!controlling && check.pair.nominated) {
      _selectPair(check.pair);
    }

    // Check if all pairs are done
    if (_state == IceState.iceChecking) {
      _checkConnectivityComplete();
    }

    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleBindingError(StunMessage msg) {
    final txId = _txIdString(msg.transactionId);
    final check = _pendingChecks.remove(txId);
    if (check != null) {
      check.pair.state = CandidatePairState.failed;
    }
    _checkConnectivityComplete();
    return const Ok(ProcessResult.empty);
  }

  // ── Connectivity checking ─────────────────────────────────────────────────

  ProcessResult _startChecks() {
    if (_state != IceState.iceGatheringComplete) return ProcessResult.empty;
    _setState(IceState.iceChecking);

    for (final remote in _remoteCandidates) {
      _pairCandidate(remote);
    }

    final packets = _doNextCheck();
    final nextTimeout = Timeout(
      at: DateTime.now().add(_checkTimeout),
      token: IceTimerToken(++_timerIdCounter),
    );
    return ProcessResult(outputPackets: packets, nextTimeout: nextTimeout);
  }

  /// Send the next waiting pair's connectivity check.
  List<OutputPacket> _doNextCheck() {
    final pair = _pairs
        .where((p) => p.state == CandidatePairState.waiting)
        .firstOrNull;
    if (pair == null) return const [];
    pair.state = CandidatePairState.inProgress;
    return _sendCheck(pair, nominated: controlling);
  }

  void _pairCandidate(IceCandidate remote) {
    for (final local in _localCandidates) {
      // Only pair same transport (UDP)
      if (local.transport != remote.transport) continue;
      // Only pair same address family (RFC 8445 §6.1.2.2)
      if (local.ip.contains(':') != remote.ip.contains(':')) continue;
      final pair = CandidatePair(local: local, remote: remote);
      pair.state = CandidatePairState.waiting;
      _pairs.add(pair);
    }
    _pairs.sort((a, b) => b.priority.compareTo(a.priority));
  }

  List<OutputPacket> _sendCheck(CandidatePair pair,
      {required bool nominated, int retransmitCount = 0}) {
    final localParams = _localParams;
    final remoteParams = _remoteParams;
    if (localParams == null || remoteParams == null) return [];

    final txId = Csprng.randomBytes(12);
    final username = '${remoteParams.usernameFragment}:${localParams.usernameFragment}';
    final priority = IceCandidate.computePriority(
      typePreference: IceCandidate.typePreferencePrflx,
      localPreference: 65535,
      componentId: 1,
    );

    final attrs = <StunAttribute>[
      UsernameAttr(username),
      PriorityAttr(priority),
      if (controlling)
        IceControllingAttr(_tieBreaker)
      else
        IceControlledAttr(_tieBreaker),
      if (nominated && controlling) const UseCandidateAttr(),
    ];

    final msg = StunMessage(
      type: StunMessageType.bindingRequest,
      transactionId: txId,
      attributes: attrs,
    );

    final raw = StunMessageBuilder.buildWithIntegrity(
        msg, Uint8List.fromList(remoteParams.password.codeUnits));

    _pendingChecks[_txIdString(txId)] = _PendingCheck(
      pair: pair,
      nominated: nominated,
      sentAt: DateTime.now(),
      retransmitCount: retransmitCount,
    );

    return [OutputPacket(data: raw, remoteIp: pair.remote.ip, remotePort: pair.remote.port)];
  }

  /// Updates an existing pair (or creates a peer-reflexive pair) when a
  /// binding request arrives from [remoteIp]:[remotePort].
  ///
  /// Returns triggered-check packets per RFC 8445 §7.3.1.4.
  List<OutputPacket> _updatePairFromRequest(
      String remoteIp, int remotePort, bool nominated) {
    final matchingPair = _pairs
        .where((p) => p.remote.ip == remoteIp && p.remote.port == remotePort)
        .firstOrNull;

    if (matchingPair != null) {
      if (nominated && !controlling) {
        matchingPair.nominated = true;
        // If already succeeded, select immediately; otherwise trigger a check.
        if (matchingPair.state == CandidatePairState.succeeded) {
          _selectPair(matchingPair);
          return const [];
        }
        // Send triggered check so we get a binding response to confirm.
        if (matchingPair.state == CandidatePairState.waiting ||
            matchingPair.state == CandidatePairState.failed) {
          matchingPair.state = CandidatePairState.inProgress;
          return _sendCheck(matchingPair, nominated: false);
        }
      }
      return const [];
    }

    // RFC 8445 §7.3.1.4: source is not known — create a peer-reflexive remote
    // candidate and trigger an immediate connectivity check to it.
    return _triggerPeerReflexiveCheck(remoteIp, remotePort, nominated);
  }

  /// Creates a peer-reflexive remote candidate for [remoteIp]:[remotePort]
  /// and immediately sends a triggered connectivity check to it.
  List<OutputPacket> _triggerPeerReflexiveCheck(
      String remoteIp, int remotePort, bool nominated) {
    if (_localCandidates.isEmpty) return const [];

    // Guard: only trigger new checks while actively checking (or already
    // connected — Chrome may send checks after ICE connects).
    if (_state != IceState.iceChecking && _state != IceState.iceConnected) {
      return const [];
    }

    // Avoid duplicates.
    final alreadyRemote =
        _remoteCandidates.any((c) => c.ip == remoteIp && c.port == remotePort);
    if (alreadyRemote) return const [];

    final priority = IceCandidate.computePriority(
      typePreference: IceCandidate.typePreferencePrflx,
      localPreference: 65535,
      componentId: 1,
    );
    final prflx = IceCandidate(
      foundation: Csprng.randomHex(4),
      componentId: 1,
      transport: 'udp',
      priority: priority,
      ip: remoteIp,
      port: remotePort,
      type: IceCandidateType.prflx,
    );
    _remoteCandidates.add(prflx);

    // Pair the new peer-reflexive remote with all local candidates.
    _pairCandidate(prflx);

    // Find the freshly-created pair and trigger a check immediately.
    final newPair = _pairs
        .where((p) =>
            p.remote.ip == remoteIp &&
            p.remote.port == remotePort &&
            p.state == CandidatePairState.waiting)
        .firstOrNull;
    if (newPair == null) return const [];

    newPair.state = CandidatePairState.inProgress;
    if (nominated && !controlling) {
      newPair.nominated = true;
    }
    return _sendCheck(newPair, nominated: controlling);
  }

  void _discoverPrflxCandidate(String ip, int port, CandidatePair triggeredBy) {
    final exists = _localCandidates.any((c) => c.ip == ip && c.port == port);
    if (exists) return;
    final priority = IceCandidate.computePriority(
      typePreference: IceCandidate.typePreferencePrflx,
      localPreference: 65535,
      componentId: 1,
    );
    final prflx = IceCandidate(
      foundation: Csprng.randomHex(4),
      componentId: 1,
      transport: 'udp',
      priority: priority,
      ip: ip,
      port: port,
      type: IceCandidateType.prflx,
    );
    _localCandidates.add(prflx);
    onLocalCandidate?.call(prflx);
  }

  void _checkConnectivityComplete() {
    // If no pairs yet, remote candidates haven't arrived — keep waiting.
    if (_pairs.isEmpty) return;
    final allDone = _pairs.every(
      (p) => p.state == CandidatePairState.succeeded ||
             p.state == CandidatePairState.failed,
    );
    if (!allDone) return;

    if (_selectedPair != null) {
      _setState(IceState.iceConnected);
    } else {
      _setState(IceState.iceFailed);
    }
  }

  void _selectPair(CandidatePair pair) {
    if (_selectedPair == null || pair.priority > _selectedPair!.priority) {
      _selectedPair = pair;
    }
  }

  Result<ProcessResult, ProtocolError> _handleIceTimer(int id) {
    if (_state != IceState.iceChecking) return const Ok(ProcessResult.empty);

    final packets = <OutputPacket>[];

    // Try next waiting pair.
    packets.addAll(_doNextCheck());

    // Retransmit in-progress checks that have exceeded the check timeout.
    final now = DateTime.now();
    for (final txId in _pendingChecks.keys.toList()) {
      final check = _pendingChecks[txId]!;
      if (now.difference(check.sentAt) >= _checkTimeout) {
        if (check.retransmitCount >= 7) {
          // RFC 8445 §14.3: max Rc=7 retransmits — fail the pair
          _pendingChecks.remove(txId);
          check.pair.state = CandidatePairState.failed;
        } else {
          // Remove old entry; _sendCheck will register the new txId
          _pendingChecks.remove(txId);
          packets.addAll(_sendCheck(check.pair,
              nominated: check.nominated,
              retransmitCount: check.retransmitCount + 1));
        }
      }
    }

    // Continue if there are still waiting or in-progress pairs.
    final hasPending = _pendingChecks.isNotEmpty ||
        _pairs.any((p) => p.state == CandidatePairState.waiting);
    if (!hasPending) {
      _checkConnectivityComplete();
      return const Ok(ProcessResult.empty);
    }

    final nextTimeout = Timeout(
      at: DateTime.now().add(_checkTimeout),
      token: IceTimerToken(++_timerIdCounter),
    );
    return Ok(ProcessResult(outputPackets: packets, nextTimeout: nextTimeout));
  }

  Result<ProcessResult, ProtocolError> _sendKeepalive() {
    final pair = _selectedPair;
    if (pair == null || _state != IceState.iceConnected) {
      return const Ok(ProcessResult.empty);
    }
    final localParams = _localParams;
    final remoteParams = _remoteParams;
    if (localParams == null || remoteParams == null) return const Ok(ProcessResult.empty);

    // Send a binding indication as keepalive (RFC 8445 §11)
    final txId = Csprng.randomBytes(12);
    final msg = StunMessage(
      type: StunMessageType.bindingIndication,
      transactionId: txId,
    );
    final raw = StunMessageBuilder.build(msg);

    final nextTimeout = Timeout(
      at: DateTime.now().add(_keepaliveInterval),
      token: IceKeepaliveToken(),
    );
    return Ok(ProcessResult(
      outputPackets: [
        OutputPacket(data: raw, remoteIp: pair.remote.ip, remotePort: pair.remote.port),
      ],
      nextTimeout: nextTimeout,
    ));
  }

  // ── STUN server gathering ─────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _handleStunServerResponse(
      StunMessage msg, String txId) {
    final req = _stunServerRequests.remove(txId);
    if (req == null) return const Ok(ProcessResult.empty);

    final xma = msg.attribute<XorMappedAddress>();
    if (xma != null) {
      // Avoid duplicate srflx candidates.
      final exists = _localCandidates.any(
          (c) => c.type == IceCandidateType.srflx && c.ip == xma.ip && c.port == xma.port);
      if (!exists) {
        final priority = IceCandidate.computePriority(
          typePreference: IceCandidate.typePreferenceSrflx,
          localPreference: 65535,
          componentId: 1,
        );
        final srflx = IceCandidate(
          foundation: Csprng.randomHex(4),
          componentId: 1,
          transport: 'udp',
          priority: priority,
          ip: xma.ip,
          port: xma.port,
          type: IceCandidateType.srflx,
          relatedAddress: req.localIp,
          relatedPort: req.localPort,
        );
        _localCandidates.add(srflx);
        onLocalCandidate?.call(srflx);
      }
    }

    // If all STUN server requests are done, complete gathering.
    if (_stunServerRequests.isEmpty) {
      return _finishGathering();
    }
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleGatheringTimeout() {
    // Discard pending STUN server requests.
    _stunServerRequests.clear();
    return _finishGathering();
  }

  Result<ProcessResult, ProtocolError> _finishGathering() {
    if (_state == IceState.iceGathering) {
      _setState(IceState.iceGatheringComplete);
      if (_remoteParams != null) {
        return Ok(_startChecks());
      }
    }
    return const Ok(ProcessResult.empty);
  }

  // ── Response builders ─────────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _buildSuccessResponse(
    Uint8List transactionId,
    String remoteIp,
    int remotePort,
    String localPassword,
  ) {
    final msg = StunMessage(
      type: StunMessageType.bindingSuccessResponse,
      transactionId: transactionId,
      attributes: [
        XorMappedAddress(ip: remoteIp, port: remotePort),
      ],
    );
    final raw = StunMessageBuilder.buildWithIntegrity(
        msg, Uint8List.fromList(localPassword.codeUnits));
    return Ok(ProcessResult(
      outputPackets: [OutputPacket(data: raw, remoteIp: remoteIp, remotePort: remotePort)],
    ));
  }

  Result<ProcessResult, ProtocolError> _buildErrorResponse(
    Uint8List transactionId,
    int code,
    String reason,
    String remoteIp,
    int remotePort,
  ) {
    final msg = StunMessage(
      type: StunMessageType.bindingErrorResponse,
      transactionId: transactionId,
      attributes: [ErrorCodeAttr(code: code, reason: reason)],
    );
    final raw = StunMessageBuilder.build(msg);
    return Ok(ProcessResult(
      outputPackets: [OutputPacket(data: raw, remoteIp: remoteIp, remotePort: remotePort)],
    ));
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  void _setState(IceState newState) {
    if (_state == newState) return;
    _state = newState;
    onStateChange?.call(newState);
  }

  static String _txIdString(Uint8List id) =>
      id.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

class _PendingCheck {
  final CandidatePair pair;
  final bool nominated;
  final DateTime sentAt;
  final int retransmitCount;
  _PendingCheck({
    required this.pair,
    required this.nominated,
    required this.sentAt,
    this.retransmitCount = 0,
  });
}

class _StunServerRequest {
  final StunServer server;
  final DateTime sentAt;
  final String localIp;
  final int localPort;
  _StunServerRequest({
    required this.server,
    required this.sentAt,
    required this.localIp,
    required this.localPort,
  });
}
