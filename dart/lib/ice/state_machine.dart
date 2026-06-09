import 'dart:collection';
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
  // Short-term-credential HMAC keys, derived once from the passwords so
  // the per-packet check/response paths don't re-encode the password.
  Uint8List? _localKey;
  Uint8List? _remoteKey;

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

  // Consent freshness (RFC 7675). Checks are paced at 5s randomized to
  // [0.8, 1.2]× (§5.1). Consent is lost after ~30s without a valid
  // response on the selected pair; tracked as a count of consecutive
  // unanswered checks (30s / 5s = 6) rather than wall-clock, so the
  // teardown is driven by the same timer the rest of the SM uses and
  // stays deterministic under test. A valid response resets the count.
  static const Duration _consentInterval = Duration(seconds: 5);
  static const int _maxMissedConsentChecks = 6;
  int _missedConsentChecks = 0;

  // Connectivity check retransmit timeout: 500ms base (RFC 8445 §14.3)
  static const Duration _checkTimeout = Duration(milliseconds: 500);

  // STUN server gathering timeout
  static const Duration _stunGatherTimeout = Duration(seconds: 3);

  /// Emitted when a local candidate is gathered.
  void Function(IceCandidate)? onLocalCandidate;

  /// Emitted when the ICE state changes.
  void Function(IceState)? onStateChange;

  /// Emitted when data arrives on the selected pair (non-STUN packet).
  void Function(Uint8List data, IpAddress remoteIp, int remotePort)? onData;

  /// `IceTransportPolicy.relay` makes the state machine ignore every
  /// non-relay candidate (both local and remote). Stored as an opaque
  /// boolean here so this module doesn't depend on the W3C enum.
  final bool _relayOnly;

  IceStateMachine({
    required this.controlling,
    List<StunServer> stunServers = const [],
    bool relayOnly = false,
  })  : _stunServers = stunServers,
        _relayOnly = relayOnly,
        _tieBreaker = Csprng.randomUint32() << 32 | Csprng.randomUint32();

  IceState get state => _state;
  CandidatePair? get selectedPair => _selectedPair;
  String? get selectedRemoteIp => _selectedPair?.remote.ip.toCanonical();
  int? get selectedRemotePort => _selectedPair?.remote.port;

  /// Live (unmodifiable) views of the candidate / pair tables. Used by
  /// `PeerConnection.getStats()` to surface per-candidate stats; never
  /// mutate from outside the state machine. Views (no copy) so a
  /// per-snapshot getStats call doesn't allocate three list copies.
  List<IceCandidate> get localCandidates =>
      UnmodifiableListView(_localCandidates);
  List<IceCandidate> get remoteCandidates =>
      UnmodifiableListView(_remoteCandidates);
  List<CandidatePair> get pairs => UnmodifiableListView(_pairs);

  // ── Public control API ───────────────────────────────────────────────────

  /// Start ICE gathering. One host candidate is emitted per [hosts]
  /// entry. STUN binding requests for srflx discovery are sourced from
  /// the first host.
  Result<ProcessResult, ProtocolError> startGathering(
    IceParameters localParams, {
    required List<HostBinding> hosts,
  }) {
    if (hosts.isEmpty) {
      return Err(const StateError('ICE: startGathering requires at least one host binding'));
    }
    _localParams = localParams;
    _localKey = Uint8List.fromList(localParams.password.codeUnits);
    _setState(IceState.iceGathering);

    // Under `IceTransportPolicy.relay` only TURN-derived relay candidates
    // are allowed — skip host emit (the socket bindings still happen in
    // the transport so the allocations have a source IP) and skip the
    // STUN srflx round-trip below.
    if (!_relayOnly) {
      for (final host in hosts) {
        final foundation = Csprng.randomHex(4);
        // Loopback candidates only form usable pairs when the peer is on
        // the same host — common in E2E tests. When they do, prefer
        // them: same-host loopback is cheaper and more reliable than
        // forcing UDP across non-loopback adapters (notably on Windows,
        // which can refuse the latter with errno 1214). On real networks
        // the loopback pair simply doesn't form, so non-loopback still
        // wins by default.
        final priority = IceCandidate.computePriority(
          typePreference: IceCandidate.typePreferenceHost,
          localPreference: host.ip.isLoopback ? 65535 : 32767,
          componentId: 1,
        );
        final hostCandidate = IceCandidate(
          foundation: foundation,
          componentId: 1,
          transport: 'udp',
          priority: priority,
          ip: host.ip,
          port: host.port,
          type: IceCandidateType.host,
        );
        _localCandidates.add(hostCandidate);
        onLocalCandidate?.call(hostCandidate);
      }
    }

    // Send STUN Binding Requests to STUN servers for srflx candidates,
    // sourced from the first host binding.
    if (!_relayOnly && _stunServers.isNotEmpty) {
      final firstHost = hosts.first;
      final packets = <OutputPacket>[];
      for (final server in _stunServers) {
        final txId = Csprng.randomBytes(12);
        final msg = StunMessage(
          type: StunMessageType.bindingRequest,
          transactionId: txId,
        );
        final raw = StunMessageBuilder.build(msg);
        packets.add(OutputPacket(
          data: raw,
          remoteIp: server.host,
          remotePort: server.port,
          localIp: firstHost.ip,
        ));
        _stunServerRequests[_txIdString(txId)] = _StunServerRequest(
          server: server,
          sentAt: DateTime.now(),
          localIp: firstHost.ip,
          localPort: firstHost.port,
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

  /// Emit a relay candidate gathered from a TURN allocation that the
  /// transport owns. `raddr`/`rport` carry the host binding the
  /// allocation was sourced from — required by RFC 8839 §5.1 for peer
  /// pair scoring.
  ///
  /// Mirrors [addRemoteCandidate]'s pair-and-check side effects: pairs
  /// the new local against every known remote, and (when the state
  /// machine is already running checks) returns the first connectivity
  /// check on the new pair so the transport can put it on the wire.
  Result<ProcessResult, ProtocolError> addLocalRelayCandidate({
    required IpAddress relayedIp,
    required int relayedPort,
    required IpAddress relatedAddress,
    required int relatedPort,
  }) {
    final candidate = IceCandidate(
      foundation: Csprng.randomHex(4),
      componentId: 1,
      transport: 'udp',
      priority: IceCandidate.computePriority(
        typePreference: IceCandidate.typePreferenceRelay,
        localPreference: 65535,
        componentId: 1,
      ),
      ip: relayedIp,
      port: relayedPort,
      type: IceCandidateType.relay,
      relatedAddress: relatedAddress,
      relatedPort: relatedPort,
    );
    _localCandidates.add(candidate);
    onLocalCandidate?.call(candidate);
    _pairLocalCandidate(candidate);
    if (_state == IceState.iceChecking) {
      final packets = _doNextCheck();
      if (packets.isNotEmpty) {
        final nextTimeout = Timeout(
          at: DateTime.now().add(_checkTimeout),
          token: IceTimerToken(++_timerIdCounter),
        );
        return Ok(ProcessResult(
            outputPackets: packets, nextTimeout: nextTimeout));
      }
    }
    return const Ok(ProcessResult.empty);
  }

  void _pairLocalCandidate(IceCandidate local) {
    for (final remote in _remoteCandidates) {
      _addPair(local, remote);
    }
    _pairs.sort((a, b) => b.priority.compareTo(a.priority));
  }

  /// Cartesian-product helper shared by [_pairCandidate] and
  /// [_pairLocalCandidate]. RFC 8445 §6.1.2.2: only pairs candidates
  /// of the same transport (UDP here) and address family; each
  /// `(local, remote)` coordinate may exist at most once in the
  /// check list. Trickle ICE can drive the same coordinate through
  /// here multiple times, so the dedup is gated on insert.
  void _addPair(IceCandidate local, IceCandidate remote) {
    if (local.transport != remote.transport) return;
    if (local.ip.isV6 != remote.ip.isV6) return;
    if (_pairs.any((p) =>
        _sameCoords(p.local, local) && _sameCoords(p.remote, remote))) {
      return;
    }
    _pairs.add(CandidatePair(local: local, remote: remote)
      ..state = CandidatePairState.waiting);
  }

  /// Two candidates produce the same connectivity-check coordinate iff
  /// their `(type, transport, ip, port)` tuple matches. `type` is part
  /// of the key because host vs prflx at the same `(ip, port)` are
  /// RFC-distinct candidates with different priorities and selection
  /// semantics.
  static bool _sameCoords(IceCandidate a, IceCandidate b) =>
      a.type == b.type &&
      a.transport == b.transport &&
      a.ip == b.ip &&
      a.port == b.port;

  /// Add a remote ICE candidate (Trickle ICE).
  ///
  /// Returns a [ProcessResult] that may include an initial STUN check to send.
  Result<ProcessResult, ProtocolError> addRemoteCandidate(
      IceCandidate candidate) {
    // Defense in depth: even with [_relayOnly] the peer may still trickle
    // host/srflx candidates (W3C doesn't require both sides to share a
    // policy). Drop them silently — pairing them would defeat the
    // privacy guarantee of the policy.
    if (_relayOnly && candidate.type != IceCandidateType.relay) {
      return const Ok(ProcessResult.empty);
    }
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
  /// Restart ICE (RFC 8445 §9 / W3C `restartIce`): discard the local
  /// candidates, pairs, and pending checks, then re-gather with the new
  /// [localParams] over the same sockets. The selected pair and consent
  /// tracking are reset so connectivity is re-validated under the new
  /// credentials.
  ///
  /// [clearRemote] is true for the side that *initiates* the restart (its
  /// peer's fresh credentials haven't arrived yet, so the old ones must be
  /// dropped); false for the side answering a restart offer, which has just
  /// applied the peer's new credentials and must keep them.
  Result<ProcessResult, ProtocolError> restart(
    IceParameters localParams, {
    required List<HostBinding> hosts,
    required bool clearRemote,
  }) {
    _localCandidates.clear();
    _pairs.clear();
    _pendingChecks.clear();
    _stunServerRequests.clear();
    _selectedPair = null;
    _missedConsentChecks = 0;
    if (clearRemote) {
      _remoteCandidates.clear();
      _remoteParams = null;
      _remoteKey = null;
    }
    _state = IceState.iceNew;
    return startGathering(localParams, hosts: hosts);
  }

  Result<ProcessResult, ProtocolError> setRemoteParameters(
      IceParameters params) {
    _remoteParams = params;
    _remoteKey = Uint8List.fromList(params.password.codeUnits);
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
          remoteIp: pair.remote.ip.toCanonical(),
          remotePort: pair.remote.port,
          localIp: pair.local.ip,
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
    required IpAddress remoteIp,
    required int remotePort,
    IpAddress? localIp,
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
      return _handleBindingRequest(msg, remoteIp, remotePort, packet, localIp);
    } else if (msg.type == StunMessageType.bindingSuccessResponse) {
      // Check if this is a response to a STUN server gathering request.
      final txId = _txIdString(msg.transactionId);
      if (_stunServerRequests.containsKey(txId)) {
        return _handleStunServerResponse(msg, txId);
      }
      return _handleBindingResponse(msg, remoteIp, remotePort, packet);
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
    if (token is IceConsentToken) {
      return _handleConsentTimer();
    }
    if (token is IceGatheringTimeoutToken) {
      return _handleGatheringTimeout();
    }
    return const Ok(ProcessResult.empty);
  }

  // ── STUN message handling ─────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _handleBindingRequest(
    StunMessage msg,
    IpAddress remoteAddr,
    int remotePort,
    Uint8List rawPacket,
    IpAddress? localIp,
  ) {
    final remoteParams = _remoteParams;
    if (remoteParams == null) {
      // Connectivity check from the peer arrived before
      // setRemoteDescription processed their ICE credentials — RFC 8445
      // §7.3.1 leaves the response to implementation discretion. Replying
      // with `400 Bad Request` causes some peers (notably Chrome on
      // Windows) to fail the candidate pair and stop retrying, killing
      // the only working ICE path before the answer is parsed. Silently
      // drop instead so the peer's normal STUN retransmit eventually
      // catches us with credentials in hand.
      return const Ok(ProcessResult.empty);
    }

    // Validate USERNAME
    final usernameAttr = msg.attribute<UsernameAttr>();
    if (usernameAttr == null) {
      return _buildErrorResponse(msg.transactionId, 400, 'Bad Request', remoteAddr, remotePort, localIp);
    }
    final localParams = _localParams!;
    final expectedUsername = '${localParams.usernameFragment}:${remoteParams.usernameFragment}';
    if (usernameAttr.username != expectedUsername) {
      return _buildErrorResponse(msg.transactionId, 401, 'Unauthorized', remoteAddr, remotePort, localIp);
    }

    // Validate MESSAGE-INTEGRITY. The peer signs connectivity-check
    // requests with our password (RFC 8445 §7.3.1.1 short-term
    // credentials), so recompute the HMAC-SHA1 over the received bytes
    // and reject a missing or forged tag with 401. Without this a blind
    // attacker who has only learned the ufrags (e.g. from one leaked
    // offer) could inject Binding Requests.
    final integrityAttr = msg.attribute<MessageIntegrityAttr>();
    if (integrityAttr == null) {
      return _buildErrorResponse(msg.transactionId, 400, 'Bad Request', remoteAddr, remotePort, localIp);
    }
    if (!StunMessageBuilder.verifyMessageIntegrity(rawPacket, _localKey!)) {
      return _buildErrorResponse(msg.transactionId, 401, 'Unauthorized', remoteAddr, remotePort, localIp);
    }

    // Role-conflict resolution (RFC 8445 §7.3.1.1). Both agents may
    // momentarily believe they hold the same role (e.g. ICE restart, or
    // an aggressive peer). The request carries the sender's role +
    // tie-breaker; if it collides with ours, the larger tie-breaker
    // keeps its role and the smaller switches. Checked only after
    // MESSAGE-INTEGRITY so a spoofed request can't force a role flip.
    final roleConflict =
        _resolveRoleConflict(msg, remoteAddr, remotePort, localIp);
    if (roleConflict != null) return roleConflict;

    // Check if NOMINATED (for controlled agent)
    final nominated = msg.attribute<UseCandidateAttr>() != null;

    // Find or create matching pair; may return triggered-check packets
    // (RFC 8445 §7.3.1.4) and, for a controlled agent honouring
    // USE-CANDIDATE, transition us to connected.
    final wasConnected = _state == IceState.iceConnected;
    final triggeredPackets =
        _updatePairFromRequest(remoteAddr, remotePort, nominated, localIp);
    final justConnected =
        !wasConnected && _state == IceState.iceConnected;

    // Build success response
    final successResult = _buildSuccessResponse(
        msg.transactionId, remoteAddr, remotePort, _localKey!, localIp);
    if (!successResult.isOk) return successResult;

    final allPackets = [
      ...successResult.value.outputPackets,
      ...triggeredPackets,
    ];
    return Ok(ProcessResult(
      outputPackets: allPackets,
      // Arm the consent-freshness timer on the connect transition (RFC 7675).
      nextTimeout: justConnected ? _consentTimeout() : null,
    ));
  }

  /// RFC 8445 §7.3.1.1 role-conflict resolution. Returns a 487 error
  /// response when this agent must keep its role (the peer should
  /// switch), `null` when there is no conflict or when this agent
  /// switched roles (the caller then proceeds to answer the request
  /// normally under the new role).
  Result<ProcessResult, ProtocolError>? _resolveRoleConflict(
    StunMessage msg,
    IpAddress remoteAddr,
    int remotePort,
    IpAddress? localIp,
  ) {
    // A conflict exists only when the peer claims the same role we hold;
    // its tie-breaker is then in the matching attribute.
    final theirTieBreaker = controlling
        ? msg.attribute<IceControllingAttr>()?.tieBreaker
        : msg.attribute<IceControlledAttr>()?.tieBreaker;
    if (theirTieBreaker == null) return null;

    if (_tieBreakerGe(_tieBreaker, theirTieBreaker)) {
      // We win — keep our role and tell the peer to yield.
      return _buildErrorResponse(msg.transactionId, 487, 'Role Conflict',
          remoteAddr, remotePort, localIp, signWith: _localKey);
    }
    _switchRole(); // we lose — yield to the peer
    return null;
  }

  /// Single chokepoint for ICE role flips (RFC 8445 §7.3.1). Both the
  /// inbound-request resolver and the inbound-487 handler funnel through
  /// here so the invariant "role only flips after a resolved conflict"
  /// has one home.
  void _switchRole() {
    controlling = !controlling;
  }

  /// Unsigned 64-bit `a >= b`. Tie-breakers fill all 64 bits, so the high
  /// bit can be set; comparing as signed Dart ints would mis-order them.
  /// Flipping the sign bit maps unsigned ordering onto signed comparison.
  /// Assumes 64-bit ints (native VM); the `0x8000…` literal and full-width
  /// tie-breakers don't survive the dart2js 53-bit int, but webdartc only
  /// targets the native VM.
  static bool _tieBreakerGe(int a, int b) =>
      (a ^ 0x8000000000000000) >= (b ^ 0x8000000000000000);

  Result<ProcessResult, ProtocolError> _handleBindingResponse(
    StunMessage msg,
    IpAddress remoteAddr,
    int remotePort,
    Uint8List rawPacket,
  ) {
    final txId = _txIdString(msg.transactionId);
    final check = _pendingChecks[txId];
    if (check == null) return const Ok(ProcessResult.empty);

    // Verify MESSAGE-INTEGRITY before acting on the response. We signed
    // the request with the peer's password, and the peer signs the
    // success response with that same password (RFC 8445 §7.2.5.2.1), so
    // recompute the HMAC over the received bytes. A forged or unsigned
    // response is discarded — leave the pending check in place so a
    // genuine retransmit can still complete it.
    final remoteKey = _remoteKey;
    if (remoteKey == null ||
        !StunMessageBuilder.verifyMessageIntegrity(rawPacket, remoteKey)) {
      return const Ok(ProcessResult.empty);
    }
    _pendingChecks.remove(txId);

    // Any valid authenticated response on the selected pair refreshes
    // consent (RFC 7675 §5.1) — including the periodic consent checks.
    if (_state == IceState.iceConnected && check.pair == _selectedPair) {
      _missedConsentChecks = 0;
    }

    // Mark pair as succeeded
    check.pair.state = CandidatePairState.succeeded;
    check.pair.roundTripTimeMs =
        DateTime.now().difference(check.sentAt).inMilliseconds;

    // Check XOR-MAPPED-ADDRESS for peer-reflexive candidate discovery
    final xma = msg.attribute<XorMappedAddress>();
    if (xma != null) {
      if (xma.address != check.pair.local.ip || xma.port != check.pair.local.port) {
        // Peer-reflexive candidate discovered — add to local candidates
        _discoverPrflxCandidate(xma.address, xma.port, check.pair);
      }
    }

    // Nominate if controlling
    var justConnected = false;
    if (controlling && check.nominated) {
      check.pair.nominated = true;
      justConnected = _selectPair(check.pair);
    } else if (!controlling && check.pair.nominated) {
      justConnected = _selectPair(check.pair);
    }

    // Check if all pairs are done
    if (_state == IceState.iceChecking) {
      _checkConnectivityComplete();
    }

    // Arm the consent-freshness timer the moment we connect (RFC 7675).
    if (justConnected) {
      return Ok(ProcessResult(nextTimeout: _consentTimeout()));
    }
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleBindingError(StunMessage msg) {
    final txId = _txIdString(msg.transactionId);
    final check = _pendingChecks.remove(txId);

    // 487 Role Conflict (RFC 8445 §7.2.5.1): the peer kept its role and
    // told us to switch. Flip our role and re-issue the check on the same
    // pair so the connectivity check can complete under the new role.
    final err = msg.attribute<ErrorCodeAttr>();
    if (err?.code == 487 && check != null) {
      _switchRole();
      check.pair.state = CandidatePairState.waiting;
      return Ok(ProcessResult(
          outputPackets:
              _sendCheck(check.pair, nominated: controlling)));
    }

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
      _addPair(local, remote);
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

    final raw = StunMessageBuilder.buildWithIntegrity(msg, _remoteKey!);

    _pendingChecks[_txIdString(txId)] = _PendingCheck(
      pair: pair,
      nominated: nominated,
      sentAt: DateTime.now(),
      retransmitCount: retransmitCount,
    );

    return [
      OutputPacket(
        data: raw,
        remoteIp: pair.remote.ip.toCanonical(),
        remotePort: pair.remote.port,
        localIp: pair.local.ip,
      ),
    ];
  }

  /// Updates an existing pair (or creates a peer-reflexive pair) when a
  /// binding request arrives from [remoteAddr]:[remotePort].
  ///
  /// Returns triggered-check packets per RFC 8445 §7.3.1.4.
  List<OutputPacket> _updatePairFromRequest(IpAddress remoteAddr, int remotePort,
      bool nominated, IpAddress? localIp) {
    // When the controlled agent receives a USE-CANDIDATE binding request
    // on a specific local socket, that's the pair the peer is trying to
    // nominate — match on (local, remote) so we don't accidentally mark
    // a different (non-routable) local pair as nominated just because
    // it shares the same remote candidate. Falls back to remote-only
    // match when the receive path didn't provide a local IP.
    Iterable<CandidatePair> candidates = _pairs
        .where((p) => p.remote.ip == remoteAddr && p.remote.port == remotePort);
    if (localIp != null) {
      final localMatches = candidates.where((p) => p.local.ip == localIp);
      if (localMatches.isNotEmpty) candidates = localMatches;
    }
    final matchingPair = candidates.firstOrNull;

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
    return _triggerPeerReflexiveCheck(remoteAddr, remotePort, nominated);
  }

  /// Creates a peer-reflexive remote candidate for [remoteIp]:[remotePort]
  /// and immediately sends a triggered connectivity check to it.
  ///
  /// RFC 8445 §7.3.1.4: "If the source transport address of the request does
  /// not match any existing remote candidates, it represents a new peer-
  /// reflexive remote candidate." §7.3.1.5 then says the USE-CANDIDATE
  /// nomination on such a pair is recorded and honored once the pair's
  /// triggered check succeeds.
  ///
  /// This path must fire regardless of whether we have already started
  /// connectivity checking locally. Firefox, in particular, sends its first
  /// Binding Request (as controlling agent, carrying USE-CANDIDATE) from an
  /// ephemeral source port that is not in any candidate it advertises —
  /// webdartc may still be in iceGathering/iceGatheringComplete at that
  /// point. Skip only for terminally dead states.
  List<OutputPacket> _triggerPeerReflexiveCheck(
      IpAddress remoteAddr, int remotePort, bool nominated) {
    if (_localCandidates.isEmpty) return const [];

    // Terminal states: the agent is no longer processing checks.
    if (_state == IceState.iceFailed ||
        _state == IceState.iceDisconnected ||
        _state == IceState.iceClosed) {
      return const [];
    }

    // Under relay-only, a STUN request from an unknown source IP means
    // the peer reached us off-relay (or the peer's relay's mapping
    // shifted). Don't promote it to a paired prflx — the policy says
    // only relay-paired flows count.
    if (_relayOnly) return const [];

    // Avoid duplicates.
    final alreadyRemote =
        _remoteCandidates.any((c) => c.ip == remoteAddr && c.port == remotePort);
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
      ip: remoteAddr,
      port: remotePort,
      type: IceCandidateType.prflx,
    );
    _remoteCandidates.add(prflx);

    // Pair the new peer-reflexive remote with all local candidates.
    _pairCandidate(prflx);

    // Find the freshly-created pair and trigger a check immediately.
    final newPair = _pairs
        .where((p) =>
            p.remote.ip == remoteAddr &&
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

  void _discoverPrflxCandidate(IpAddress addr, int port, CandidatePair triggeredBy) {
    if (_relayOnly) return; // prflx is just srflx-by-another-name; banned in relay mode.
    final exists = _localCandidates.any((c) => c.ip == addr && c.port == port);
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
      ip: addr,
      port: port,
      type: IceCandidateType.prflx,
    );
    _localCandidates.add(prflx);
    onLocalCandidate?.call(prflx);
  }

  void _checkConnectivityComplete() {
    // If no pairs yet, remote candidates haven't arrived — keep waiting.
    if (_pairs.isEmpty) return;

    // A pair being selected is what transitions us to iceConnected — that
    // happens in [_selectPair], not here.  This method only decides when
    // to give up.  For the controlled agent in particular, a succeeded-
    // but-not-yet-nominated pair must NOT cause a failed transition,
    // because the USE-CANDIDATE request from the controlling agent may
    // still be in flight (RFC 8445 §7.3.1.5).  We therefore only declare
    // failure when every pair has terminally failed — a succeeded pair is
    // proof of bidirectional reachability and we should wait for the
    // controlling agent to nominate it.
    final allFailed = _pairs
        .every((p) => p.state == CandidatePairState.failed);
    if (allFailed && _selectedPair == null) {
      _setState(IceState.iceFailed);
    }
  }

  /// Selects [pair]. Returns true if this call newly transitioned the
  /// agent to `iceConnected`, so the caller can arm the consent-freshness
  /// timer (RFC 7675) on the ProcessResult it returns.
  bool _selectPair(CandidatePair pair) {
    if (_selectedPair == null || pair.priority > _selectedPair!.priority) {
      final wasConnected = _state == IceState.iceConnected;
      _selectedPair = pair;
      // First nomination immediately concludes connectivity checking
      // (RFC 8445 §8.1.1).  Don't wait for in-progress pairs to time out.
      if (_state == IceState.iceChecking) {
        _setState(IceState.iceConnected);
      }
      if (!wasConnected && _state == IceState.iceConnected) {
        _missedConsentChecks = 0;
        return true;
      }
    }
    return false;
  }

  Result<ProcessResult, ProtocolError> _handleIceTimer(int id) {
    if (_state != IceState.iceChecking) return const Ok(ProcessResult.empty);

    final packets = <OutputPacket>[];

    // Try next waiting pair.
    packets.addAll(_doNextCheck());

    // Retransmit in-progress checks that have exceeded their timeout.
    // Exponential backoff per RFC 8445 §14.3: 500ms * 2^retransmitCount.
    final now = DateTime.now();
    for (final txId in _pendingChecks.keys.toList()) {
      final check = _pendingChecks[txId]!;
      final rtoMs = (500 * (1 << check.retransmitCount)).clamp(0, 16000);
      if (now.difference(check.sentAt) >= Duration(milliseconds: rtoMs)) {
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

    // Exponential backoff: 500ms * 2^min(retransmitCount), capped at 16s
    // Find the minimum retransmit count among pending checks to pace the
    // timer appropriately for the next expected retransmit.
    var minRc = 0;
    for (final check in _pendingChecks.values) {
      if (minRc == 0 || check.retransmitCount < minRc) {
        minRc = check.retransmitCount;
      }
    }
    final delayMs = (500 * (1 << minRc)).clamp(0, 16000);
    final nextTimeout = Timeout(
      at: DateTime.now().add(Duration(milliseconds: delayMs)),
      token: IceTimerToken(++_timerIdCounter),
    );
    return Ok(ProcessResult(outputPackets: packets, nextTimeout: nextTimeout));
  }

  /// Consent-freshness tick (RFC 7675 §5.1). After
  /// [_maxMissedConsentChecks] consecutive checks without a valid response
  /// on the selected pair, consent is lost and we cease transmission on the
  /// pair (→ `iceDisconnected`). Otherwise send an authenticated check on
  /// the selected pair (which doubles as the keepalive, §6) and re-arm.
  Result<ProcessResult, ProtocolError> _handleConsentTimer() {
    final pair = _selectedPair;
    if (pair == null || _state != IceState.iceConnected) {
      return const Ok(ProcessResult.empty); // not connected — stop the timer
    }

    if (_missedConsentChecks >= _maxMissedConsentChecks) {
      // Consent expired — abandon the pair and signal a transient loss.
      pair.state = CandidatePairState.failed;
      _selectedPair = null;
      _setState(IceState.iceDisconnected);
      return const Ok(ProcessResult.empty); // no re-arm
    }

    _missedConsentChecks++; // reset to 0 when a valid response arrives
    return Ok(ProcessResult(
      outputPackets: _sendCheck(pair, nominated: false),
      nextTimeout: _consentTimeout(),
    ));
  }

  /// Next consent check, paced at [_consentInterval] randomized to
  /// [0.8, 1.2]× per RFC 7675 §5.1 to avoid synchronization across peers.
  Timeout _consentTimeout() {
    final jitterMicros = (_consentInterval.inMicroseconds *
            (0.8 + 0.4 * (Csprng.randomUint32() / 0xFFFFFFFF)))
        .round();
    return Timeout(
      at: DateTime.now().add(Duration(microseconds: jitterMicros)),
      token: IceConsentToken(),
    );
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
          (c) => c.type == IceCandidateType.srflx && c.ip == xma.address && c.port == xma.port);
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
          ip: xma.address,
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
    IpAddress remoteAddr,
    int remotePort,
    Uint8List localKey,
    IpAddress? localIp,
  ) {
    final msg = StunMessage(
      type: StunMessageType.bindingSuccessResponse,
      transactionId: transactionId,
      attributes: [
        XorMappedAddress(address: remoteAddr, port: remotePort),
      ],
    );
    final raw = StunMessageBuilder.buildWithIntegrity(msg, localKey);
    return Ok(ProcessResult(
      outputPackets: [
        OutputPacket(
          data: raw,
          remoteIp: remoteAddr.toCanonical(),
          remotePort: remotePort,
          localIp: localIp,
        ),
      ],
    ));
  }

  Result<ProcessResult, ProtocolError> _buildErrorResponse(
    Uint8List transactionId,
    int code,
    String reason,
    IpAddress remoteAddr,
    int remotePort,
    IpAddress? localIp, {
    Uint8List? signWith,
  }) {
    final msg = StunMessage(
      type: StunMessageType.bindingErrorResponse,
      transactionId: transactionId,
      attributes: [ErrorCodeAttr(code: code, reason: reason)],
    );
    // 487 Role Conflict answers an already-authenticated request, so it
    // carries MESSAGE-INTEGRITY; auth-failure errors (400/401) are sent
    // unsigned since we couldn't validate the sender's credentials.
    final raw = signWith != null
        ? StunMessageBuilder.buildWithIntegrity(msg, signWith)
        : StunMessageBuilder.build(msg);
    return Ok(ProcessResult(
      outputPackets: [
        OutputPacket(
          data: raw,
          remoteIp: remoteAddr.toCanonical(),
          remotePort: remotePort,
          localIp: localIp,
        ),
      ],
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
  final IpAddress localIp;
  final int localPort;
  _StunServerRequest({
    required this.server,
    required this.sentAt,
    required this.localIp,
    required this.localPort,
  });
}
