// ignore_for_file: unawaited_futures
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../api/setting_engine.dart';
import '../core/state_machine.dart';
import '../dtls/state_machine.dart';
import '../ice/state_machine.dart';
import '../rtp/parser.dart';
import '../sctp/state_machine.dart';
import '../srtp/context.dart';
import '../stun/parser.dart';
import '../turn/state_machine.dart';

/// The only module in webdartc that uses dart:io.
///
/// Owns one [RawDatagramSocket] per bound local IP, dispatches incoming
/// packets to the correct state machine, and drives timers on behalf of
/// all protocol modules. Per-IP bind makes ICE replies leave on the
/// same interface that received the request — each socket has a fixed
/// source IP, sidestepping the kernel's source-address selection.
final class TransportController {
  /// Bound sockets keyed by their bind IP. Wildcard fallback uses
  /// `0.0.0.0` as the key; per-interface bind uses the interface IPs.
  final Map<IpAddress, RawDatagramSocket> _sockets = {};

  /// Last local IP a DTLS record arrived on. DTLS state-machine output
  /// packets don't carry a localIp, but Windows refuses to bounce UDP
  /// across non-loopback interfaces — so when no other localIp signal
  /// is available, sending the reply from the same socket that just
  /// received a record is the most reliable choice.
  IpAddress? _lastInboundLocalIp;

  IceStateMachine? _ice;
  DtlsStateMachine? _dtls;
  SrtpContext? _srtp;
  SctpStateMachine? _sctp;

  List<TurnServer> _turnServers = const [];

  /// Active allocations keyed by the TURN server's (IP, port). Record
  /// keys give value equality without per-datagram string interpolation
  /// in the dispatch path.
  final Map<(IpAddress, int), TurnAllocation> _allocations = {};

  /// Reverse lookup: relayed transport address → allocation. Keying by
  /// IP only is safe under the one-allocation-per-server policy
  /// (each TURN server gives back a distinct relayed IP).
  final Map<IpAddress, TurnAllocation> _relayedAllocations = {};

  /// (ip, port) pairs to advertise as ICE host candidates. Computed once
  /// at [start] time from the resolved bind list; for the wildcard fallback
  /// the IP is the auto-detected non-loopback address rather than 0.0.0.0.
  List<HostBinding> _bindings = const [];
  List<HostBinding> get bindings => _bindings;

  /// Snapshot of TURN allocations the transport currently owns.
  /// Primarily for tests + diagnostics; membership order isn't part of
  /// the contract.
  List<TurnAllocation> get turnAllocations => _allocations.values.toList();

  /// First advertised IP, in canonical text form. Used by the legacy
  /// single-IP SDP builder path.
  String get localAddress =>
      _bindings.isEmpty ? '0.0.0.0' : _bindings.first.ip.toCanonical();

  /// First advertised port. Used by the legacy single-IP SDP builder path.
  int get localPort => _bindings.isEmpty ? 0 : _bindings.first.port;

  final _timers = <String, Timer>{};

  /// Monotonic clock for transport-cc arrival timestamps.  Stopwatch uses
  /// clock_gettime(CLOCK_MONOTONIC) — immune to NTP adjustments and wall-
  /// clock jumps that DateTime.now() is subject to.
  final Stopwatch _arrivalClock = Stopwatch()..start();

  /// Called when an RTP packet is decrypted (SRTP → RTP).
  /// The [int] parameter is the monotonic arrival timestamp in microseconds.
  void Function(Uint8List, int arrivalUs)? onRtp;

  /// Called when an RTCP packet is decrypted (SRTCP → RTCP).
  void Function(Uint8List)? onRtcp;

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /// Bind UDP sockets and start receiving packets. One socket per IP
  /// resolved by [_resolveBindAddresses].
  Future<void> start({
    SettingEngine settingEngine = const SettingEngine(),
    int port = 0,
  }) async {
    final bindIps = await _resolveBindAddresses(settingEngine);

    if (bindIps.isEmpty) {
      // Wildcard fallback: bind 0.0.0.0 and advertise the auto-detected
      // non-loopback IP as the host candidate.
      final socket =
          await RawDatagramSocket.bind(InternetAddress.anyIPv4, port);
      final bindIp = IpAddress.fromBytes(socket.address.rawAddress);
      socket.listen(
        (event) => _onEvent(socket, bindIp, event),
        onError: _onSocketError,
      );
      _sockets[bindIp] = socket;
      _bindings = [(ip: await _findLocalIpv4(), port: socket.port)];
      _startTurnAllocations();
      return;
    }

    final sockets = await Future.wait([
      for (final ip in bindIps)
        RawDatagramSocket.bind(InternetAddress(ip.toCanonical()), port),
    ]);
    final bindings = <HostBinding>[];
    for (var i = 0; i < bindIps.length; i++) {
      final ip = bindIps[i];
      final socket = sockets[i];
      socket.listen(
        (event) => _onEvent(socket, ip, event),
        onError: _onSocketError,
      );
      _sockets[ip] = socket;
      bindings.add((ip: ip, port: socket.port));
    }
    _bindings = bindings;
    _startTurnAllocations();
  }

  /// Resolves the IPs the transport will bind to from a [SettingEngine].
  /// Public for tests; production callers go through [start].
  static Future<List<IpAddress>> _resolveBindAddresses(
      SettingEngine engine) async {
    if (engine.bindAddresses != null) {
      return engine.bindAddresses!.map(IpAddress.parse).toList();
    }

    final nonLoopback = <IpAddress>[];
    final loopback = <IpAddress>[];
    try {
      final interfaces = await NetworkInterface.list(
        type: InternetAddressType.IPv4,
        includeLoopback: true,
      );
      for (final iface in interfaces) {
        if (engine.interfaceFilter != null &&
            !engine.interfaceFilter!(iface)) {
          continue;
        }
        for (final addr in iface.addresses) {
          final ip = IpAddress.fromBytes(addr.rawAddress);
          if (ip.isLoopback) {
            loopback.add(ip);
          } else {
            nonLoopback.add(ip);
          }
        }
      }
    } catch (_) {
      // NetworkInterface.list can fail in restricted environments;
      // caller falls back to wildcard bind.
    }

    if (nonLoopback.isEmpty) {
      // Pure-loopback host — return loopback regardless of the engine's
      // includeLoopbackCandidate setting, so we always have at least one
      // bind to land on.
      return loopback;
    }
    if (engine.includeLoopbackCandidate) {
      return [...nonLoopback, ...loopback];
    }
    return nonLoopback;
  }

  /// First non-loopback IPv4 from interface enumeration, or `127.0.0.1`
  /// if none. Used by the wildcard-bind fallback for the advertised
  /// candidate IP.
  static Future<IpAddress> _findLocalIpv4() async {
    final ips = await _resolveBindAddresses(const SettingEngine());
    return ips.firstWhere(
      (ip) => !ip.isLoopback,
      orElse: () => ips.isEmpty ? IpAddress.parse('127.0.0.1') : ips.first,
    );
  }

  /// Forward a ProcessResult produced by an ICE control action (e.g.
  /// setRemoteParameters, addRemoteCandidate) to the transport so that
  /// the initial STUN binding requests and their retransmit timers are sent.
  void handleIceControl(Result<ProcessResult, ProtocolError> result) {
    if (!result.isOk) return;
    _sendOutputPackets(result.value.outputPackets);
    _scheduleTimeout(result.value.nextTimeout, 'ice-init');
  }

  Future<void> stop() async {
    // Send Refresh(lifetime=0) for each allocation so coturn frees the
    // relay slot immediately rather than waiting out the (default 10 min)
    // server-side timeout. The Refresh ack arrives after the socket
    // closes; we don't wait for it.
    for (final allocation in _allocations.values) {
      if (allocation.state == TurnState.allocated) {
        final res = allocation.close();
        if (res.isOk) _sendOutputPackets(res.value.outputPackets);
      }
    }
    _allocations.clear();
    _relayedAllocations.clear();
    _pendingPermissions.clear();
    _peerSendCounts.clear();
    _pendingChannelBinds.clear();
    for (final timer in _timers.values) {
      timer.cancel();
    }
    _timers.clear();
    for (final socket in _sockets.values) {
      socket.close();
    }
    _sockets.clear();
  }

  // ── Module attachment ─────────────────────────────────────────────────────

  void attachIce(IceStateMachine ice) {
    _ice = ice;
  }

  void attachDtls(DtlsStateMachine dtls) {
    _dtls = dtls;
  }

  void attachSrtp(SrtpContext srtp) {
    _srtp = srtp;
  }

  void attachSctp(SctpStateMachine sctp) {
    _sctp = sctp;
  }

  /// Register TURN servers to allocate against during [start]. Must be
  /// called before [start]; allocations happen once, immediately after
  /// sockets bind.
  void attachTurnServers(List<TurnServer> servers) {
    _turnServers = servers;
  }

  void _startTurnAllocations() {
    if (_turnServers.isEmpty || _bindings.isEmpty) return;
    final host = _bindings.first;
    for (final server in _turnServers) {
      if (server.transport != 'udp' || server.secure) {
        // PR 3 wires UDP only; turns:/transport=tcp lands in a later PR.
        continue;
      }
      final serverIp = IpAddress.parse(server.host);
      final endpoint = (serverIp, server.port);
      final allocation = TurnAllocation(
        serverIp: serverIp,
        serverPort: server.port,
        username: server.username,
        password: server.password,
      );
      allocation.onAllocated = (relayedIp, relayedPort) {
        _relayedAllocations[relayedIp] = allocation;
        final res = _ice?.addLocalRelayCandidate(
          relayedIp: relayedIp,
          relayedPort: relayedPort,
          relatedAddress: host.ip,
          relatedPort: host.port,
        );
        if (res != null && res.isOk) {
          _sendOutputPackets(res.value.outputPackets);
          _scheduleTimeout(res.value.nextTimeout, 'ice-check');
        }
      };
      allocation.onPeerData = (peerIp, peerPort, payload) {
        // Re-dispatch as if direct from the peer so upper layers don't
        // need to know it came via TURN. Loop-safe: `peerIp` ≠ TURN
        // server, so the next `_allocations[(peerIp, peerPort)]` misses.
        final relayedIp = allocation.relayedAddress;
        if (relayedIp == null) return;
        _dispatch(payload, _arrivalClock.elapsedMicroseconds, peerIp, peerPort,
            relayedIp);
      };
      allocation.onPermissionResult = (peerIp, _) {
        _pendingPermissions.remove((allocation, peerIp));
      };
      allocation.onChannelResult = (channel, peerIp, peerPort, bound) {
        _pendingChannelBinds.remove((allocation, peerIp, peerPort));
        if (!bound) {
          // Server refused to bind this peer (rare: 486 quota, 437 alloc
          // mismatch, etc.). Freeze the counter past the threshold so
          // we don't keep retrying forever; future sends stay on the
          // heavier Send-indication path.
          _peerSendCounts[(allocation, peerIp, peerPort)] = -1;
        }
      };
      _allocations[endpoint] = allocation;
      final res = allocation.start();
      if (res.isOk) {
        _sendOutputPackets(res.value.outputPackets);
        _scheduleTimeout(
            res.value.nextTimeout, 'turn-${server.host}:${server.port}');
      }
    }
  }

  /// Start the DTLS handshake, sending the initial flight and scheduling
  /// the retransmit timer.  Must be called after ICE reaches connected.
  void startDtlsHandshake({
    required IpAddress remoteIp,
    required int remotePort,
  }) {
    final dtls = _dtls;
    if (dtls == null) return;
    final result = dtls.startHandshake(
      remoteIp: remoteIp,
      remotePort: remotePort,
    );
    if (result.isOk) {
      _sendOutputPackets(result.value.outputPackets);
      _scheduleTimeout(result.value.nextTimeout, 'dtls-retransmit');
    }
  }

  // ── Packet sending ────────────────────────────────────────────────────────

  void sendRtp(Uint8List rtpBytes) {
    final pair = _ice?.selectedPair;
    if (pair == null) return;
    _sendUdp(rtpBytes, pair.remote.ip.toCanonical(), pair.remote.port,
        localIp: pair.local.ip);
  }

  void sendSctp(Uint8List sctpBytes) {
    final pair = _ice?.selectedPair;
    if (pair == null) return;
    // SCTP over DTLS: encrypt via DTLS then send
    if (_dtls != null) {
      final result = _dtls!.sendApplicationData(sctpBytes);
      if (result.isOk) {
        _sendOutputPackets(result.value.outputPackets);
        _scheduleTimeout(result.value.nextTimeout, 'dtls-app');
      }
    } else {
      _sendUdp(sctpBytes, pair.remote.ip.toCanonical(), pair.remote.port,
          localIp: pair.local.ip);
    }
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  // Debug logging — set WEBDARTC_DEBUG=1 env var to trace packet flow.
  static final bool _debug = Platform.environment['WEBDARTC_DEBUG'] == '1';

  /// UDP errors that surface asynchronously on the socket stream — most
  /// commonly send failures the OS reports after the synchronous
  /// `send()` already returned (e.g. on Windows, sending UDP from a
  /// host-IP socket back to the same host IP raises errno 1214
  /// ERROR_BAD_NET_NAME on a later tick). Network errors are non-fatal
  /// in UDP — ICE pair probing tolerates per-pair failure — so we
  /// swallow them rather than letting them tear down the isolate.
  void _onSocketError(Object error, StackTrace stack) {
    if (_debug) stderr.writeln('[transport] socket error: $error');
  }

  void _onEvent(
      RawDatagramSocket socket, IpAddress bindIp, RawSocketEvent event) {
    if (event != RawSocketEvent.read) return;
    // Record arrival timestamp immediately, before any processing.
    final arrivalUs = _arrivalClock.elapsedMicroseconds;
    final datagram = socket.receive();
    if (datagram == null) return;

    final data = datagram.data;
    final remoteIp = IpAddress.fromBytes(datagram.address.rawAddress);
    final remotePort = datagram.port;

    if (_debug) {
      stderr.writeln('[transport] RX ${data.length}b from $remoteIp:$remotePort'
          ' on local=$bindIp'
          ' b0=${data.isNotEmpty ? data[0].toRadixString(16) : "?"}');
      if (data.isNotEmpty && (data[0] == 0x00 || data[0] == 0x01)) {
        final hex = data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
        stderr.writeln('[transport] RX hex: $hex');
      }
    }

    _dispatch(data, arrivalUs, remoteIp, remotePort, bindIp);
  }

  void _dispatch(Uint8List data, int arrivalUs, IpAddress remoteIp,
      int remotePort, IpAddress localIp) {
    if (data.isEmpty) return;
    final firstByte = data[0];

    // Allocation lookup gated on isNotEmpty so the common no-TURN flow
    // stays a single Map.isEmpty check per datagram.
    if (_allocations.isNotEmpty) {
      final allocation = _allocations[(remoteIp, remotePort)];
      if (allocation != null) {
        final result = allocation.processInput(
          data,
          remoteIp: remoteIp,
          remotePort: remotePort,
        );
        if (result.isOk) {
          _sendOutputPackets(result.value.outputPackets);
          _scheduleTimeout(
              result.value.nextTimeout, 'turn-$remoteIp:$remotePort');
        }
        return;
      }
    }

    if (StunParser.isStun(data)) {
      _processIce(data, remoteIp, remotePort, localIp);
    } else if (firstByte >= 20 && firstByte <= 63) {
      // DTLS record layer. Remember which local socket received it so
      // outgoing DTLS records (which don't carry a localIp in their
      // OutputPackets) reply on the same interface — important on
      // Windows where cross-interface UDP sends can fail.
      _lastInboundLocalIp = localIp;
      _processDtls(data, remoteIp, remotePort);
    } else if (firstByte >= 128 && firstByte <= 191) {
      // RTP or RTCP
      _processSrtp(data, arrivalUs);
    }
    // Else: unknown — discard
  }

  void _processIce(Uint8List data, IpAddress remoteIp, int remotePort,
      IpAddress localIp) {
    final ice = _ice;
    if (ice == null) return;
    final result = ice.processInput(data,
        remoteIp: remoteIp, remotePort: remotePort, localIp: localIp);
    if (result.isOk) {
      _sendOutputPackets(result.value.outputPackets);
      _scheduleTimeout(result.value.nextTimeout, 'ice-check');
    }
  }

  void _processDtls(Uint8List data, IpAddress remoteIp, int remotePort) {
    final dtls = _dtls;
    if (dtls == null) return;
    final result = dtls.processInput(data,
        remoteIp: remoteIp, remotePort: remotePort);
    if (result.isOk) {
      _sendOutputPackets(result.value.outputPackets);
      _scheduleTimeout(result.value.nextTimeout, 'dtls-retransmit');
    }
  }

  void _processSrtp(Uint8List data, int arrivalUs) {
    final srtp = _srtp;
    if (srtp == null) return;

    if (RtpParser.isRtcp(data)) {
      final decResult = srtp.decryptRtcp(data);
      if (decResult.isOk) {
        onRtcp?.call(decResult.value);
      } else if (_debug) {
        stderr.writeln('[transport] SRTCP decrypt failed: ${decResult.error} len=${data.length}');
      }
    } else {
      final decResult = srtp.decryptRtp(data);
      if (decResult.isOk) {
        onRtp?.call(decResult.value, arrivalUs);
      } else if (_debug) {
        stderr.writeln('[transport] SRTP decrypt failed: ${decResult.error} len=${data.length}'
            ' b0=0x${data[0].toRadixString(16)}');
      }
    }
  }

  /// Sends each packet as a raw UDP datagram. Callers must pass packets
  /// whose [OutputPacket.data] is already wire-ready — STUN messages,
  /// DTLS records, or DTLS-encrypted application data. SCTP state-machine
  /// output is plaintext SCTP and must go through [sendSctp] instead, which
  /// applies the DTLS encryption layer first.
  void _sendOutputPackets(List<OutputPacket> packets) {
    for (final pkt in packets) {
      // If the IP is not a valid address (hostname), resolve it asynchronously.
      if (InternetAddress.tryParse(pkt.remoteIp) == null && !_dnsCache.containsKey(pkt.remoteIp)) {
        _resolveAndSend(pkt);
      } else {
        _sendUdp(pkt.data, pkt.remoteIp, pkt.remotePort, localIp: pkt.localIp);
      }
    }
  }

  Future<void> _resolveAndSend(OutputPacket pkt) async {
    final addr = await _resolveAddress(pkt.remoteIp);
    if (addr != null) {
      _sendUdp(pkt.data, pkt.remoteIp, pkt.remotePort, localIp: pkt.localIp);
    }
  }

  /// Resolve a hostname to an IPv4 address (cached).
  final Map<String, InternetAddress?> _dnsCache = {};

  Future<InternetAddress?> _resolveAddress(String host) async {
    final cached = _dnsCache[host];
    if (cached != null) return cached;
    // Try parsing as IP first.
    final parsed = InternetAddress.tryParse(host);
    if (parsed != null) {
      _dnsCache[host] = parsed;
      return parsed;
    }
    // DNS lookup.
    try {
      final results = await InternetAddress.lookup(host,
          type: InternetAddressType.IPv4);
      if (results.isNotEmpty) {
        _dnsCache[host] = results.first;
        return results.first;
      }
    } catch (_) {
      // DNS resolution failed.
    }
    return null;
  }

  /// Pick a socket for sending. Prefers the one bound to [localIp]; if
  /// that's null, prefers the socket bound to the ICE-selected pair's
  /// local IP (DTLS / SCTP OutputPackets don't carry localIp, but we
  /// still want them to leave on the nominated interface — important on
  /// Windows where cross-interface UDP sends can fail with errno 1214
  /// even between local IPs). Final fallback is any socket — used for
  /// the lookup misses (wildcard bind: socket key is `0.0.0.0`, candidate
  /// IP is auto-detected).
  RawDatagramSocket? _selectSocket(IpAddress? localIp) {
    if (localIp != null) {
      final s = _sockets[localIp];
      if (s != null) return s;
    }
    // Prefer the interface a DTLS record most recently arrived on
    // (set in `_dispatch`): DTLS state-machine outputs carry no
    // localIp and ICE may have selected a pair that doesn't actually
    // route on Windows even though its connectivity check raced ahead
    // of the loopback pair's. The receive interface is the most
    // authoritative signal of "the peer can reach us here".
    if (_lastInboundLocalIp != null) {
      final s = _sockets[_lastInboundLocalIp!];
      if (s != null) return s;
    }
    final selected = _ice?.selectedPair?.local.ip;
    if (selected != null) {
      final s = _sockets[selected];
      if (s != null) return s;
    }
    return _sockets.values.firstOrNull;
  }

  void _sendUdp(Uint8List data, String ip, int port, {IpAddress? localIp}) {
    if (_relayedAllocations.isNotEmpty) {
      final allocation = _selectRelayAllocation(localIp);
      if (allocation != null) {
        final peer = IpAddress.tryParse(ip);
        // Skip the wrap when the destination is itself a TURN server we
        // own an allocation against — that's a TURN-internal send
        // (Allocate / Refresh / CreatePermission / ChannelBind) and
        // re-wrapping would loop instead of reaching the server.
        if (peer != null && !_allocations.containsKey((peer, port))) {
          _sendViaRelay(allocation, peer, port, data);
          return;
        }
      }
    }
    _sendUdpRaw(data, ip, port, localIp: localIp);
  }

  /// Pick the allocation whose relayed transport address is the source
  /// of this packet. DTLS / SCTP records arrive with no explicit
  /// `localIp` — when ICE has nominated a relay pair, fall back to its
  /// local so their traffic follows the same path the connectivity
  /// checks took.
  TurnAllocation? _selectRelayAllocation(IpAddress? localIp) {
    final src = localIp ?? _ice?.selectedPair?.local.ip;
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
        if (res.isOk) _sendOutputPackets(res.value.outputPackets);
      }
      return;
    }
    final out = wrapped.value;
    // Straight to the raw send: skip the wrap-gate (this is the wrapped
    // packet on its way to the TURN server) and avoid a second
    // `IpAddress.tryParse` on the same destination.
    _sendUdpRaw(out.data, out.remoteIp, out.remotePort);

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
    final count = (_peerSendCounts[key] ?? 0);
    if (count < 0) return; // frozen after a prior bind failure
    final next = count + 1;
    _peerSendCounts[key] = next;
    if (next < _channelPromotionThreshold) return;
    if (!_pendingChannelBinds.add(key)) return;
    final res = allocation.bindChannel(peer, port);
    if (res.isOk) _sendOutputPackets(res.value.outputPackets);
  }

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

  void _sendUdpRaw(Uint8List data, String ip, int port, {IpAddress? localIp}) {
    try {
      var addr = InternetAddress.tryParse(ip);
      if (addr == null) {
        // Check DNS cache for hostname (async resolution happens in _sendOutputPackets).
        addr = _dnsCache[ip];
        if (addr == null) return;
      }
      // Skip IPv6 destinations on IPv4-only sockets.
      if (addr.type == InternetAddressType.IPv6) return;
      if (_debug) {
        stderr.writeln('[transport] TX ${data.length}b to $ip:$port'
            ' from local=${localIp ?? "?"}'
            ' b0=${data.isNotEmpty ? data[0].toRadixString(16) : "?"}');
        if (data.isNotEmpty && (data[0] == 0x00 || data[0] == 0x01)) {
          final hex = data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
          stderr.writeln('[transport] TX hex: $hex');
        }
      }
      final socket = _selectSocket(localIp);
      socket?.send(data, addr, port);
    } catch (_) {
      // Network errors are non-fatal in UDP
    }
  }

  /// Public hook so PeerConnection can schedule SCTP-layer timers
  /// (T3-rtx, T1-init, T1-cookie) returned from `_sctp.sendData()` /
  /// `_sctp.openDataChannel()`. Without this, lost SCTP DATA chunks
  /// would never trigger retransmission because the per-chunk T3-rtx
  /// `nextTimeout` returned by the SCTP state machine was being
  /// discarded by the DataChannel send callback in peer_connection.dart.
  void scheduleSctpTimeout(Timeout? timeout) =>
      _scheduleTimeout(timeout, 'sctp');

  void _scheduleTimeout(Timeout? timeout, String key) {
    if (timeout == null) return;
    _timers[key]?.cancel();
    final delay = timeout.at.difference(DateTime.now());
    final effectiveDelay = delay.isNegative ? Duration.zero : delay;
    _timers[key] = Timer(effectiveDelay, () => _fireTimeout(timeout.token, key));
  }

  void _fireTimeout(TimerToken token, String key) {
    _timers.remove(key);
    final result = _dispatchTimeout(token);
    if (result == null) return;
    if (result.isOk) {
      // SCTP timer outputs are raw SCTP packets — they must be encrypted
      // via DTLS before going on the wire (the receive-side dispatch only
      // recognises DTLS records 0x14–0x3F and discards anything else).
      // The receive-path SCTP handler in PeerConnection routes ProcessResult
      // packets through `sendSctp`, but timer-driven retransmits land here
      // and would otherwise bypass DTLS, leaving every T3-rtx attempt to be
      // dropped by the peer.
      final isSctpTimer = token is SctpT1InitToken ||
          token is SctpT1CookieToken ||
          token is SctpT3RtxToken;
      if (isSctpTimer) {
        for (final pkt in result.value.outputPackets) {
          sendSctp(pkt.data);
        }
      } else {
        _sendOutputPackets(result.value.outputPackets);
      }
      _scheduleTimeout(result.value.nextTimeout, key);
    }
  }

  Result<ProcessResult, ProtocolError>? _dispatchTimeout(TimerToken token) {
    if (token is IceTimerToken || token is IceKeepaliveToken || token is IceGatheringTimeoutToken) {
      return _ice?.handleTimeout(token) ?? const Ok(ProcessResult.empty);
    }
    if (token is DtlsRetransmitToken) {
      return _dtls?.handleTimeout(token) ?? const Ok(ProcessResult.empty);
    }
    if (token is SctpT1InitToken ||
        token is SctpT1CookieToken ||
        token is SctpT3RtxToken) {
      return _sctp?.handleTimeout(token) ?? const Ok(ProcessResult.empty);
    }
    if (token is TurnRefreshToken ||
        token is TurnPermissionRefreshToken ||
        token is TurnChannelRefreshToken) {
      // Token doesn't identify its allocation, so broadcast and let each
      // SM ignore tokens that aren't theirs. Output is sent inline so a
      // simultaneous refresh on multiple allocations isn't dropped.
      _broadcastTurnTimeout(token);
      return const Ok(ProcessResult.empty);
    }
    return null;
  }

  void _broadcastTurnTimeout(TimerToken token) {
    for (final entry in _allocations.entries) {
      final res = entry.value.handleTimeout(token);
      if (res.isOk && res.value.outputPackets.isNotEmpty) {
        _sendOutputPackets(res.value.outputPackets);
        _scheduleTimeout(
            res.value.nextTimeout, 'turn-${entry.key.$1}:${entry.key.$2}');
      }
    }
  }
}
