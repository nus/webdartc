/// TURN allocation client state machine (RFC 5766 / RFC 8656).
///
/// Pure state machine — no I/O.
library;

import 'dart:typed_data';

import '../core/state_machine.dart';
import '../crypto/csprng.dart';
import '../stun/builder.dart';
import '../stun/message.dart';
import '../stun/parser.dart';
import 'channel_data.dart';

enum TurnState {
  idle,
  allocating,
  authenticating,
  allocated,
  closing,
  closed,
}

/// Parsed `turn:` / `turns:` URI per RFC 7065. Credentials come from the
/// enclosing IceServer (W3C splits URL list and credentials).
final class TurnServer {
  final String host;
  final int port;
  final String username;
  final String password;

  /// `udp` (RFC 7065 default for `turn:`) or `tcp`. PR 3 only wires UDP.
  final String transport;

  /// True for `turns:` URIs.
  final bool secure;

  const TurnServer({
    required this.host,
    required this.port,
    required this.username,
    required this.password,
    required this.transport,
    required this.secure,
  });

  /// Parse a `turn:` / `turns:` URI per RFC 7065 §3.1. Returns null on
  /// syntax error or when credentials are missing — TURN always needs
  /// long-term credentials, so silently dropping such URIs would mask
  /// configuration mistakes from the caller.
  static TurnServer? parse(
    String uri, {
    required String? username,
    required String? credential,
  }) {
    final secure = uri.startsWith('turns:');
    if (!secure && !uri.startsWith('turn:')) return null;
    if (username == null || credential == null) return null;
    final body = uri.substring(secure ? 6 : 5);
    final qIdx = body.indexOf('?');
    final hostPort = qIdx < 0 ? body : body.substring(0, qIdx);
    final query = qIdx < 0 ? '' : body.substring(qIdx + 1);
    var transport = secure ? 'tcp' : 'udp';
    for (final kv in query.split('&')) {
      if (kv.startsWith('transport=')) {
        transport = kv.substring('transport='.length).toLowerCase();
      }
    }
    final defaultPort = secure ? 5349 : 3478;
    final colonIdx = hostPort.lastIndexOf(':');
    int port;
    String host;
    if (colonIdx <= 0) {
      host = hostPort;
      port = defaultPort;
    } else {
      final parsedPort = int.tryParse(hostPort.substring(colonIdx + 1));
      if (parsedPort == null) return null;
      host = hostPort.substring(0, colonIdx);
      port = parsedPort;
    }
    if (host.isEmpty) return null;
    return TurnServer(
      host: host,
      port: port,
      username: username,
      password: credential,
      transport: transport,
      secure: secure,
    );
  }
}

/// IANA protocol number for UDP — the value the client puts in
/// REQUESTED-TRANSPORT per RFC 5766 §14.7.
const int turnRequestedTransportUdp = 17;

/// RFC 5766 §6.2 default allocation lifetime in seconds. The server may
/// grant a different value in the Allocate success response.
const int turnDefaultLifetimeSeconds = 600;

final class _PendingRequest {
  final int method;
  final Object? context;
  final DateTime sentAt;
  _PendingRequest({required this.method, this.context, DateTime? sentAt})
      : sentAt = sentAt ?? DateTime.now();
}

/// Per RFC 5389 §7.2.1, total STUN retransmit budget is RTO × (2^Rc − 1) ≈
/// 39.5 s; prune `_pending` entries older than that so a server that drops
/// a response can't leak indefinitely.
const Duration _pendingTtl = Duration(seconds: 40);

final class TurnAllocation implements ProtocolStateMachine {
  final IpAddress serverIp;
  final int serverPort;
  final String username;
  final String password;

  /// Requested allocation lifetime in seconds. The server may grant a
  /// shorter value; the actual value comes back in LIFETIME and drives
  /// the refresh timer.
  final int requestedLifetime;

  TurnState _state = TurnState.idle;
  IpAddress? _relayedAddress;
  int? _relayedPort;
  String? _realm;
  Uint8List? _nonce;
  Uint8List? _key;
  int _grantedLifetime = 0;

  final Map<String, _PendingRequest> _pending = {};

  final Set<IpAddress> _permissions = {};

  // Bidirectional channel ↔ peer tables for O(1) lookup on both send and
  // recv. Channel numbers come from the application range (0x4000-0x7FFF).
  final Map<(IpAddress, int), int> _peerToChannel = {};
  final Map<int, (IpAddress, int)> _channelToPeer = {};
  int _nextChannel = channelNumberMin;

  void Function(IpAddress relayedIp, int relayedPort)? onAllocated;
  void Function(IpAddress peerIp, int peerPort, Uint8List payload)? onPeerData;
  void Function(String reason)? onAllocationFailed;
  void Function()? onClosed;
  void Function(IpAddress peerIp, bool granted)? onPermissionResult;
  void Function(int channel, IpAddress peerIp, int peerPort, bool bound)?
      onChannelResult;

  TurnAllocation({
    required this.serverIp,
    required this.serverPort,
    required this.username,
    required this.password,
    this.requestedLifetime = turnDefaultLifetimeSeconds,
  });

  TurnState get state => _state;
  IpAddress? get relayedAddress => _relayedAddress;
  int? get relayedPort => _relayedPort;
  int get grantedLifetime => _grantedLifetime;

  bool hasPermission(IpAddress peer) => _permissions.contains(peer);
  int? channelFor(IpAddress peerIp, int peerPort) =>
      _peerToChannel[(peerIp, peerPort)];

  // ── Public control ─────────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> start() {
    if (_state != TurnState.idle) {
      return Err(StateError('TURN: start() called in state $_state'));
    }
    _state = TurnState.allocating;
    final txId = Csprng.randomTransactionId();
    _registerPending(
        txId, _PendingRequest(method: StunMessageType.allocateRequest));
    final msg = StunMessage(
      type: StunMessageType.allocateRequest,
      transactionId: txId,
      attributes: [
        const RequestedTransportAttr(turnRequestedTransportUdp),
        LifetimeAttr(requestedLifetime),
      ],
    );
    return Ok(ProcessResult(
        outputPackets: [_toServer(StunMessageBuilder.build(msg))]));
  }

  Result<ProcessResult, ProtocolError> createPermission(IpAddress peerIp) {
    if (_state != TurnState.allocated) {
      return Err(StateError('TURN: createPermission requires allocated state'));
    }
    return Ok(_sendCreatePermission(peerIp));
  }

  Result<ProcessResult, ProtocolError> bindChannel(
      IpAddress peerIp, int peerPort) {
    if (_state != TurnState.allocated) {
      return Err(StateError('TURN: bindChannel requires allocated state'));
    }
    final channel = _peerToChannel[(peerIp, peerPort)] ??
        _allocateChannel(peerIp, peerPort);
    return Ok(_sendChannelBind(channel, peerIp, peerPort));
  }

  /// Wrap [payload] for sending to peer through the allocation. Uses
  /// ChannelData when a channel is bound, otherwise a Send indication
  /// (which requires a prior `createPermission` for [peerIp]).
  Result<OutputPacket, ProtocolError> wrapSend(
      IpAddress peerIp, int peerPort, Uint8List payload) {
    if (_state != TurnState.allocated) {
      return Err(StateError('TURN: wrapSend requires allocated state'));
    }
    final channel = _peerToChannel[(peerIp, peerPort)];
    if (channel != null) {
      return Ok(_toServer(buildChannelData(channel, payload)));
    }
    if (!_permissions.contains(peerIp)) {
      return Err(StateError(
          'TURN: no permission for $peerIp — call createPermission first'));
    }
    final msg = StunMessage(
      type: StunMessageType.sendIndication,
      transactionId: Csprng.randomTransactionId(),
      attributes: [
        XorPeerAddress(address: peerIp, port: peerPort),
        DataAttr(payload),
      ],
    );
    return Ok(_toServer(StunMessageBuilder.build(msg)));
  }

  Result<ProcessResult, ProtocolError> close() {
    if (_state != TurnState.allocated) {
      return Err(StateError('TURN: close() requires allocated state'));
    }
    _state = TurnState.closing;
    return Ok(_sendRefresh(lifetime: 0));
  }

  // ── ProtocolStateMachine ───────────────────────────────────────────────

  @override
  Result<ProcessResult, ProtocolError> processInput(
    Uint8List packet, {
    required IpAddress remoteIp,
    required int remotePort,
  }) {
    if (remoteIp != serverIp || remotePort != serverPort) {
      return Err(StateError(
          'TURN: packet from unexpected peer $remoteIp:$remotePort'));
    }

    if (isChannelData(packet)) {
      final frame = parseChannelData(packet);
      if (frame == null) {
        return Err(const ParseError('TURN: invalid ChannelData frame'));
      }
      final peer = _channelToPeer[frame.channel];
      if (peer != null) {
        onPeerData?.call(peer.$1, peer.$2, frame.payload);
      }
      return Ok(ProcessResult.empty);
    }

    final parsed = StunParser.parse(packet);
    if (parsed.isErr) return Err(parsed.error);
    return _handleStun(parsed.value);
  }

  @override
  Result<ProcessResult, ProtocolError> handleTimeout(TimerToken token) {
    switch (token) {
      case TurnRefreshToken():
        return _state == TurnState.allocated
            ? Ok(_sendRefresh(lifetime: requestedLifetime))
            : Ok(ProcessResult.empty);
      case TurnPermissionRefreshToken(:final peerIp):
        return _state == TurnState.allocated && _permissions.contains(peerIp)
            ? Ok(_sendCreatePermission(peerIp))
            : Ok(ProcessResult.empty);
      case TurnChannelRefreshToken(:final channel):
        final peer = _channelToPeer[channel];
        return _state == TurnState.allocated && peer != null
            ? Ok(_sendChannelBind(channel, peer.$1, peer.$2))
            : Ok(ProcessResult.empty);
      default:
        return Ok(ProcessResult.empty);
    }
  }

  // ── Internal: outbound request builders ────────────────────────────────

  /// Build all post-Allocate requests via a single path so each call site
  /// can't forget to register the pending entry or wrap with the
  /// long-term credential.
  ProcessResult _sendAuthedRequest({
    required int method,
    required List<StunAttribute> attrs,
    Object? context,
    Timeout? nextTimeout,
  }) {
    final txId = Csprng.randomTransactionId();
    _registerPending(
        txId, _PendingRequest(method: method, context: context));
    final msg = StunMessage(type: method, transactionId: txId, attributes: attrs);
    return ProcessResult(
        outputPackets: [_toServer(_buildAuthed(msg))],
        nextTimeout: nextTimeout);
  }

  ProcessResult _sendRefresh({required int lifetime}) => _sendAuthedRequest(
        method: StunMessageType.refreshRequest,
        attrs: [LifetimeAttr(lifetime)],
      );

  ProcessResult _sendCreatePermission(IpAddress peerIp) => _sendAuthedRequest(
        method: StunMessageType.createPermissionRequest,
        attrs: [XorPeerAddress(address: peerIp, port: 0)],
        context: peerIp,
      );

  ProcessResult _sendChannelBind(
          int channel, IpAddress peerIp, int peerPort) =>
      _sendAuthedRequest(
        method: StunMessageType.channelBindRequest,
        attrs: [
          ChannelNumberAttr(channel),
          XorPeerAddress(address: peerIp, port: peerPort),
        ],
        context: (channel, peerIp, peerPort),
      );

  ProcessResult _resendAllocate() => _sendAuthedRequest(
        method: StunMessageType.allocateRequest,
        attrs: [
          const RequestedTransportAttr(turnRequestedTransportUdp),
          LifetimeAttr(requestedLifetime),
        ],
      );

  Uint8List _buildAuthed(StunMessage msg) {
    final key = _key;
    final realm = _realm;
    final nonce = _nonce;
    if (key == null || realm == null || nonce == null) {
      return StunMessageBuilder.build(msg);
    }
    final withCreds = StunMessage(
      type: msg.type,
      transactionId: msg.transactionId,
      attributes: [
        ...msg.attributes,
        UsernameAttr(username),
        RealmAttr(realm),
        NonceAttr(nonce),
      ],
    );
    return StunMessageBuilder.buildWithIntegrity(withCreds, key,
        fingerprint: false);
  }

  /// Allocate next sequentially-assigned channel and bind it to the peer
  /// in both lookup tables. Wraps back to [channelNumberMin] when the
  /// 0x4000-0x7FFF range is exhausted; an existing binding at the wrap
  /// target would be silently overwritten, so callers should cap at
  /// ~16k simultaneous peers per allocation.
  int _allocateChannel(IpAddress peerIp, int peerPort) {
    final channel = _nextChannel++;
    if (_nextChannel > channelNumberMax) _nextChannel = channelNumberMin;
    _peerToChannel[(peerIp, peerPort)] = channel;
    _channelToPeer[channel] = (peerIp, peerPort);
    return channel;
  }

  void _registerPending(Uint8List txId, _PendingRequest req) {
    // Prune so a dropped server response can't leak the entry forever.
    if (_pending.isNotEmpty) {
      final cutoff = DateTime.now().subtract(_pendingTtl);
      _pending.removeWhere((_, e) => e.sentAt.isBefore(cutoff));
    }
    _pending[_txIdKey(txId)] = req;
  }

  // ── Internal: response handling ────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _handleStun(StunMessage msg) {
    if (msg.isIndication) return _handleIndication(msg);
    final pending = _pending.remove(_txIdKey(msg.transactionId));
    if (pending == null) return Ok(ProcessResult.empty);
    return switch (pending.method) {
      StunMessageType.allocateRequest => _handleAllocateResponse(msg),
      StunMessageType.refreshRequest => _handleRefreshResponse(msg),
      StunMessageType.createPermissionRequest =>
        _handleCreatePermissionResponse(msg, pending.context! as IpAddress),
      StunMessageType.channelBindRequest => _handleChannelBindResponse(
          msg, pending.context! as (int, IpAddress, int)),
      _ => Ok(ProcessResult.empty),
    };
  }

  Result<ProcessResult, ProtocolError> _handleIndication(StunMessage msg) {
    if (msg.type != StunMessageType.dataIndication) {
      return Ok(ProcessResult.empty);
    }
    final peer = msg.attribute<XorPeerAddress>();
    final data = msg.attribute<DataAttr>();
    if (peer == null || data == null) {
      return Err(const ParseError('TURN: DataIndication missing PEER/DATA'));
    }
    onPeerData?.call(peer.address, peer.port, data.data);
    return Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleAllocateResponse(
      StunMessage msg) {
    if (msg.isErrorResponse) {
      final code = msg.attribute<ErrorCodeAttr>()?.code;
      if (code == StunErrorCode.unauthorized &&
          _state == TurnState.allocating) {
        return _onAllocateChallenge(msg);
      }
      if (code == StunErrorCode.staleNonce) {
        _refreshNonce(msg);
        return Ok(_resendAllocate());
      }
      _fail('Allocate rejected: ${code ?? "?"} '
          '${msg.attribute<ErrorCodeAttr>()?.reason ?? ""}');
      return Ok(ProcessResult.empty);
    }
    if (!msg.isSuccessResponse) return Ok(ProcessResult.empty);
    return _onAllocateSuccess(msg);
  }

  Result<ProcessResult, ProtocolError> _onAllocateChallenge(StunMessage msg) {
    final realm = msg.attribute<RealmAttr>()?.realm;
    final nonce = msg.attribute<NonceAttr>()?.nonce;
    if (realm == null || nonce == null) {
      return Err(const ParseError(
          'TURN: 401 response missing REALM or NONCE'));
    }
    _realm = realm;
    _nonce = nonce;
    _key = StunMessageBuilder.longTermKey(username, realm, password);
    _state = TurnState.authenticating;
    return Ok(_resendAllocate());
  }

  Result<ProcessResult, ProtocolError> _onAllocateSuccess(StunMessage msg) {
    final relayed = msg.attribute<XorRelayedAddress>();
    if (relayed == null) {
      return Err(const ParseError(
          'TURN: success without XOR-RELAYED-ADDRESS'));
    }
    _relayedAddress = relayed.address;
    _relayedPort = relayed.port;
    _grantedLifetime =
        msg.attribute<LifetimeAttr>()?.seconds ?? requestedLifetime;
    _state = TurnState.allocated;
    onAllocated?.call(relayed.address, relayed.port);
    return Ok(ProcessResult(nextTimeout: _refreshTimeout()));
  }

  Result<ProcessResult, ProtocolError> _handleRefreshResponse(StunMessage msg) {
    if (msg.isErrorResponse) {
      final code = msg.attribute<ErrorCodeAttr>()?.code;
      if (code == StunErrorCode.staleNonce) {
        _refreshNonce(msg);
        return Ok(_sendRefresh(
            lifetime: _state == TurnState.closing ? 0 : requestedLifetime));
      }
      _fail('Refresh rejected: ${code ?? "?"}');
      return Ok(ProcessResult.empty);
    }
    if (_state == TurnState.closing) {
      _state = TurnState.closed;
      onClosed?.call();
      return Ok(ProcessResult.empty);
    }
    _grantedLifetime =
        msg.attribute<LifetimeAttr>()?.seconds ?? requestedLifetime;
    return Ok(ProcessResult(nextTimeout: _refreshTimeout()));
  }

  Result<ProcessResult, ProtocolError> _handleCreatePermissionResponse(
      StunMessage msg, IpAddress peerIp) {
    if (msg.isErrorResponse) {
      final code = msg.attribute<ErrorCodeAttr>()?.code;
      if (code == StunErrorCode.staleNonce) {
        _refreshNonce(msg);
        return Ok(_sendCreatePermission(peerIp));
      }
      onPermissionResult?.call(peerIp, false);
      return Ok(ProcessResult.empty);
    }
    _permissions.add(peerIp);
    onPermissionResult?.call(peerIp, true);
    return Ok(ProcessResult(
        nextTimeout: _timeoutAfter(
            const Duration(seconds: _permissionRefreshSeconds),
            TurnPermissionRefreshToken(peerIp))));
  }

  Result<ProcessResult, ProtocolError> _handleChannelBindResponse(
      StunMessage msg, (int, IpAddress, int) ctx) {
    final (channel, peerIp, peerPort) = ctx;
    if (msg.isErrorResponse) {
      final code = msg.attribute<ErrorCodeAttr>()?.code;
      if (code == StunErrorCode.staleNonce) {
        _refreshNonce(msg);
        return Ok(_sendChannelBind(channel, peerIp, peerPort));
      }
      _peerToChannel.remove((peerIp, peerPort));
      _channelToPeer.remove(channel);
      onChannelResult?.call(channel, peerIp, peerPort, false);
      return Ok(ProcessResult.empty);
    }
    // ChannelBind grants the per-IP permission implicitly (RFC 5766 §9).
    _permissions.add(peerIp);
    onChannelResult?.call(channel, peerIp, peerPort, true);
    return Ok(ProcessResult(
        nextTimeout: _timeoutAfter(
            const Duration(seconds: _channelRefreshSeconds),
            TurnChannelRefreshToken(channel))));
  }

  void _refreshNonce(StunMessage msg) {
    final nonce = msg.attribute<NonceAttr>()?.nonce;
    if (nonce != null) _nonce = nonce;
    final realm = msg.attribute<RealmAttr>()?.realm;
    if (realm != null && realm != _realm) {
      _realm = realm;
      _key = StunMessageBuilder.longTermKey(username, realm, password);
    }
  }

  void _fail(String reason) {
    _state = TurnState.closed;
    onAllocationFailed?.call(reason);
  }

  /// Refresh halfway through the granted lifetime — leaves headroom for
  /// the round-trip and any retry without depending on a real-time clock.
  Timeout _refreshTimeout() {
    final seconds = (_grantedLifetime ~/ _refreshDivisor)
        .clamp(_minRefreshIntervalSeconds, _grantedLifetime);
    return _timeoutAfter(Duration(seconds: seconds), TurnRefreshToken());
  }

  Timeout _timeoutAfter(Duration delta, TimerToken token) =>
      Timeout(at: DateTime.now().add(delta), token: token);

  OutputPacket _toServer(Uint8List data) => OutputPacket(
        data: data,
        remoteIp: serverIp.toCanonical(),
        remotePort: serverPort,
      );

  // RFC 5766: permissions expire after 5 min, channels after 10. Refresh
  // a minute early so a server-side expiry never catches us mid-RTT.
  static const int _permissionRefreshSeconds = 240;
  static const int _channelRefreshSeconds = 540;

  // Allocation refresh schedule. Halfway through the granted lifetime is
  // the conventional choice; the floor protects against pathologically
  // short server-granted lifetimes that would otherwise schedule a
  // refresh after zero seconds.
  static const int _refreshDivisor = 2;
  static const int _minRefreshIntervalSeconds = 10;

  /// Map key for transaction IDs. 12 bytes (each 0–255) round-trip through
  /// `String.fromCharCodes` losslessly and yield a single 12-char string
  /// with value equality — cheaper than a hex encode that would allocate
  /// 12 substrings plus the join buffer per call.
  static String _txIdKey(Uint8List bytes) => String.fromCharCodes(bytes);
}
