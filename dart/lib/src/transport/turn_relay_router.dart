part of 'transport_controller.dart';

/// Routes outbound datagrams through TURN relays: wrapping sends as Send
/// indications / ChannelData, installing permissions on demand, and
/// auto-promoting busy peers to bound channels.
final class TurnRelayRouter {
  final TransportController _tc;

  TurnRelayRouter(this._tc);

  /// Reverse lookup: relayed transport address → allocation. Keying by
  /// IP only is safe under the one-allocation-per-server policy
  /// (each TURN server gives back a distinct relayed IP).
  final Map<IpAddress, TurnAllocation> _relayedAllocations = {};

  /// Permission requests in flight, so ICE / DTLS retransmits don't
  /// pile new CreatePermissions onto the TURN state machine while the
  /// first one is still being acked. Cleared on the response callback.
  final Set<(TurnAllocation, IpAddress)> _pendingPermissions = {};

  /// Per-peer send counters that drive ChannelBind auto-promotion.
  /// `-1` means "frozen" — a prior bind failed, don't try again.
  final Map<(TurnAllocation, IpAddress, int), int> _peerSendCounts = {};

  /// ChannelBind requests in flight; same role as [_pendingPermissions].
  final Set<(TurnAllocation, IpAddress, int)> _pendingChannelBinds = {};

  /// Send-indication count after which we promote a peer to a bound
  /// channel. 10 packets ≈ 200 ms of an audio stream / 1 ICE keepalive
  /// round-trip — enough to filter short-lived flows but quick enough
  /// to pay for itself on long ones.
  static const int _channelPromotionThreshold = 10;

  /// Sentinel value stored in [_peerSendCounts] after the server refused
  /// a ChannelBind. Negative so it can never collide with a real count.
  static const int _channelBindFrozen = -1;

  bool get _hasRelays => _relayedAllocations.isNotEmpty;

  void _clear() {
    _relayedAllocations.clear();
    _pendingPermissions.clear();
    _peerSendCounts.clear();
    _pendingChannelBinds.clear();
  }

  /// Pick the allocation whose relayed transport address is the source
  /// of this packet. DTLS / SCTP records arrive with no explicit
  /// `localIp` — when ICE has nominated a relay pair, fall back to its
  /// local so their traffic follows the same path the connectivity
  /// checks took.
  TurnAllocation? _selectRelayAllocation(IpAddress? localIp) {
    final src = localIp ?? _tc._ice?.selectedPair?.local.ip;
    return src == null ? null : _relayedAllocations[src];
  }

  /// Wrap [data] as a Send indication / ChannelData and forward to the
  /// allocation's server. Missing-permission Errs install a permission
  /// inline; the dropped packet is recovered by the upper-layer
  /// retransmit (ICE checks at ~500 ms).
  void _sendViaRelay(TurnAllocation allocation, IpAddress peer, int peerPort,
      Uint8List data) {
    final wrapped = allocation.wrapSend(peer, peerPort, data);
    if (wrapped.isErr) {
      if (!allocation.hasPermission(peer) &&
          _pendingPermissions.add((allocation, peer))) {
        final res = allocation.createPermission(peer);
        if (res.isOk) _tc._sendOutputPackets(res.value.outputPackets);
      }
      return;
    }
    final out = wrapped.value;
    // Straight to the raw send: skip the wrap-gate (this is the wrapped
    // packet on its way to the TURN server) and avoid a second
    // `IpAddress.tryParse` on the same destination. TCP allocations
    // ship the same wrapped bytes over the control connection instead.
    final tcp =
        _tc._turnTcpConnections[(allocation.serverIp, allocation.serverPort)];
    if (tcp != null) {
      tcp.send(out.data);
    } else {
      _tc._pool.sendRaw(out.data, out.remoteIp, out.remotePort);
    }

    // After enough traffic to a peer, promote from Send-indication
    // (~36 B overhead) to a bound channel (4 B). The state machine's
    // own `_peerToChannel` table makes future `wrapSend` calls pick
    // ChannelData automatically once the bind succeeds.
    _maybePromoteToChannel(allocation, peer, peerPort);
  }

  void _maybePromoteToChannel(
      TurnAllocation allocation, IpAddress peer, int port) {
    if (allocation.channelFor(peer, port) != null) return;
    final key = (allocation, peer, port);
    final next = _peerSendCounts.update(
        key, (c) => c == _channelBindFrozen ? c : c + 1,
        ifAbsent: () => 1);
    if (next == _channelBindFrozen) return;
    if (next < _channelPromotionThreshold) return;
    if (!_pendingChannelBinds.add(key)) return;
    final res = allocation.bindChannel(peer, port);
    if (res.isOk) _tc._sendOutputPackets(res.value.outputPackets);
  }
}
