part of 'transport_controller.dart';

/// Owns the bound UDP sockets: per-IP bind, listen with rebind recovery,
/// send-socket selection, the pending-send queue for kernel-full `send()`
/// results, and the transport-level byte/packet counters.
final class SocketPool {
  /// Bound sockets keyed by their bind IP. Wildcard fallback uses
  /// `0.0.0.0` as the key; per-interface bind uses the interface IPs.
  final Map<IpAddress, RawDatagramSocket> _sockets = {};

  /// Per-socket FIFO of UDP datagrams whose `send()` returned 0 (kernel
  /// send buffer transiently full — happens on Windows loopback after
  /// even a 2-packet burst). Drained on `RawSocketEvent.write`. Without
  /// this queue, packets are silently dropped, which on the wire looks
  /// like random loopback packet loss and stalls DTLS handshakes for
  /// seconds while the upper-layer retransmit timer fires.
  final Map<RawDatagramSocket, List<_PendingSend>> _pendingSends = {};

  /// Last local IP a DTLS record arrived on. DTLS state-machine output
  /// packets don't carry a localIp, but Windows refuses to bounce UDP
  /// across non-loopback interfaces — so when no other localIp signal
  /// is available, sending the reply from the same socket that just
  /// received a record is the most reliable choice.
  IpAddress? _lastInboundLocalIp;

  /// Set by the controller's stop(). Distinguishes our own deliberate
  /// socket close from the runtime killing a socket on an async send
  /// error, so the rebind-recovery in [_listenWithRecovery] doesn't
  /// resurrect sockets during shutdown.
  bool _stopped = false;

  /// (ip, port) pairs to advertise as ICE host candidates. Computed once
  /// at [bind] time from the resolved bind list; for the wildcard fallback
  /// the IP is the auto-detected non-loopback address rather than 0.0.0.0.
  List<HostBinding> _bindings = const [];

  /// Monotonically-increasing byte counts spanning every UDP datagram
  /// put on / taken off the wire (TURN-TCP links add theirs from the
  /// controller). Surfaced via `PeerConnection.getStats()`.
  int bytesSent = 0;
  int bytesReceived = 0;
  int packetsSent = 0;
  int packetsReceived = 0;

  /// Monotonic clock shared with the controller, used to stamp datagram
  /// arrival before dispatch.
  final int Function() _nowUs;

  /// Fired once per received datagram.
  void Function(Uint8List data, int arrivalUs, IpAddress remoteIp,
      int remotePort, IpAddress bindIp)? onDatagram;

  /// Cached-hostname lookup for send targets that aren't literal IPs
  /// (async resolution happens in the controller's send path).
  InternetAddress? Function(String host)? resolveCached;

  /// ICE-selected local IP, used as a send-socket fallback — see
  /// [_selectSocket].
  IpAddress? Function()? selectedLocalIp;

  SocketPool({required int Function() nowUs}) : _nowUs = nowUs;

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /// Bind UDP sockets and start receiving packets. One socket per IP
  /// resolved by [_resolveBindAddresses].
  Future<void> bind({
    SettingEngine settingEngine = const SettingEngine(),
    int port = 0,
  }) async {
    _stopped = false;
    final bindIps = await _resolveBindAddresses(settingEngine);

    if (bindIps.isEmpty) {
      // Wildcard fallback: bind 0.0.0.0 and advertise the auto-detected
      // non-loopback IP as the host candidate.
      final socket =
          await RawDatagramSocket.bind(InternetAddress.anyIPv4, port);
      final bindIp = IpAddress.fromBytes(socket.address.rawAddress);
      _sockets[bindIp] = socket;
      _listenWithRecovery(socket, bindIp, InternetAddress.anyIPv4);
      _bindings = [(ip: await _findLocalIpv4(), port: socket.port)];
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
      _sockets[ip] = socket;
      _listenWithRecovery(socket, ip, InternetAddress(ip.toCanonical()));
      bindings.add((ip: ip, port: socket.port));
    }
    _bindings = bindings;
  }

  /// Close every socket and drop queued sends. The controller sets
  /// [_stopped] before tearing down allocations so recovery can't
  /// resurrect sockets mid-shutdown.
  void close() {
    for (final socket in _sockets.values) {
      socket.close();
    }
    _sockets.clear();
    _pendingSends.clear();
  }

  /// Listen on [socket], and if the runtime kills it, rebind a fresh
  /// socket on the same address/port and resume.
  ///
  /// On Windows, a UDP send whose failure surfaces asynchronously (e.g.
  /// errno 1214 ERROR_BAD_NET_NAME / 1231 NETWORK_UNREACHABLE from a
  /// cross-interface ICE check on a multi-NIC host) is reported as an
  /// error event on the socket — after which the Dart runtime CLOSES the
  /// socket: every datagram arriving from then on is silently dropped.
  /// One bad connectivity check would permanently deafen the host
  /// candidate, so ICE as the controlled side never sees the peer's
  /// Binding requests and the session never connects. Rebinding the same
  /// (address, port) restores reception; in-flight upper-layer
  /// retransmits (ICE checks ~500 ms, DTLS flights) cover the sub-ms
  /// rebind gap.
  void _listenWithRecovery(
      RawDatagramSocket socket, IpAddress key, InternetAddress bindAddr) {
    // Captured eagerly: the getter throws once the runtime closes the
    // socket, and recovery is exactly the time we need it.
    final boundPort = socket.port;
    socket.listen(
      (event) => _onEvent(socket, key, event),
      onError: _onSocketError,
      onDone: () => _recoverSocket(socket, key, bindAddr, boundPort),
    );
  }

  Future<void> _recoverSocket(RawDatagramSocket dead, IpAddress key,
      InternetAddress bindAddr, int boundPort) async {
    // onDone also fires for the deliberate close() in stop() — only
    // recover sockets that died while still registered as live.
    if (_stopped || !identical(_sockets[key], dead)) return;
    // Queued datagrams belonged to the dead socket's kernel buffer; the
    // protocols retransmit, so drop rather than replay stale packets.
    _pendingSends.remove(dead);
    try {
      final fresh = await RawDatagramSocket.bind(bindAddr, boundPort);
      if (_stopped) {
        fresh.close();
        return;
      }
      _sockets[key] = fresh;
      _listenWithRecovery(fresh, key, bindAddr);
      if (TransportController._debug) {
        stderr.writeln('[transport] rebound $key:$boundPort after the '
            'runtime closed the socket on a send error');
      }
    } catch (e) {
      // Port stolen in the gap (or bind otherwise refused) — drop the
      // binding; sends fall back to the remaining sockets.
      _sockets.remove(key);
      if (TransportController._debug) {
        stderr.writeln('[transport] rebind of $key:$boundPort failed: $e');
      }
    }
  }

  /// Resolves the IPs the transport will bind to from a [SettingEngine].
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

  // ── Receive ───────────────────────────────────────────────────────────────

  /// UDP errors that surface asynchronously on the socket stream — most
  /// commonly send failures the OS reports after the synchronous
  /// `send()` already returned (e.g. on Windows, sending UDP from a
  /// host-IP socket back to the same host IP raises errno 1214
  /// ERROR_BAD_NET_NAME on a later tick). Network errors are non-fatal
  /// in UDP — ICE pair probing tolerates per-pair failure — so we
  /// swallow them rather than letting them tear down the isolate.
  void _onSocketError(Object error, StackTrace stack) {
    if (TransportController._debug) {
      stderr.writeln('[transport] socket error: $error');
    }
  }

  void _onEvent(
      RawDatagramSocket socket, IpAddress bindIp, RawSocketEvent event) {
    if (event == RawSocketEvent.write) {
      _drainPendingSends(socket);
      return;
    }
    if (event != RawSocketEvent.read) return;
    // Drain every datagram the kernel has queued for this readable event.
    // Dart's RawDatagramSocket emits a single RawSocketEvent.read when the
    // socket transitions to readable; if multiple datagrams arrive before
    // we drain, the extras stay in the OS receive buffer and only become
    // visible on the NEXT readable transition (which may not fire until
    // another packet arrives). On Windows loopback that gap stalls DTLS
    // handshakes — server flight retransmits sit unread for seconds.
    while (true) {
      final arrivalUs = _nowUs();
      final datagram = socket.receive();
      if (datagram == null) return;

      final data = datagram.data;
      final remoteIp = IpAddress.fromBytes(datagram.address.rawAddress);
      final remotePort = datagram.port;

      bytesReceived += data.length;
      packetsReceived++;

      if (TransportController._debug) {
        stderr.writeln('[transport] RX ${data.length}b from $remoteIp:$remotePort'
            ' on local=$bindIp'
            ' b0=${data.isNotEmpty ? data[0].toRadixString(16) : "?"}');
        if (data.isNotEmpty && (data[0] == 0x00 || data[0] == 0x01)) {
          final hex = data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
          stderr.writeln('[transport] RX hex: $hex');
        }
      }

      onDatagram?.call(data, arrivalUs, remoteIp, remotePort, bindIp);
    }
  }

  // ── Send ──────────────────────────────────────────────────────────────────

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
    // (set by the demuxer): DTLS state-machine outputs carry no
    // localIp and ICE may have selected a pair that doesn't actually
    // route on Windows even though its connectivity check raced ahead
    // of the loopback pair's. The receive interface is the most
    // authoritative signal of "the peer can reach us here".
    if (_lastInboundLocalIp != null) {
      final s = _sockets[_lastInboundLocalIp!];
      if (s != null) return s;
    }
    final selected = selectedLocalIp?.call();
    if (selected != null) {
      final s = _sockets[selected];
      if (s != null) return s;
    }
    return _sockets.values.firstOrNull;
  }

  /// Send one datagram, queueing it for the write event when the kernel
  /// buffer is transiently full.
  void sendRaw(Uint8List data, String ip, int port, {IpAddress? localIp}) {
    try {
      var addr = InternetAddress.tryParse(ip);
      if (addr == null) {
        // Check DNS cache for hostname (async resolution happens in the
        // controller's send path).
        addr = resolveCached?.call(ip);
        if (addr == null) return;
      }
      // Skip IPv6 destinations on IPv4-only sockets.
      if (addr.type == InternetAddressType.IPv6) return;
      if (TransportController._debug) {
        stderr.writeln('[transport] TX ${data.length}b to $ip:$port'
            ' from local=${localIp ?? "?"}'
            ' b0=${data.isNotEmpty ? data[0].toRadixString(16) : "?"}');
        if (data.isNotEmpty && (data[0] == 0x00 || data[0] == 0x01)) {
          final hex = data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
          stderr.writeln('[transport] TX hex: $hex');
        }
      }
      final socket = _selectSocket(localIp);
      if (socket == null) return;
      // If we already have a pending queue for this socket, append instead
      // of trying send() — preserving order with previously deferred packets.
      final queued = _pendingSends[socket];
      if (queued != null && queued.isNotEmpty) {
        queued.add(_PendingSend(data, addr, port));
        return;
      }
      final sent = socket.send(data, addr, port);
      if (sent > 0) {
        bytesSent += sent;
        packetsSent++;
      } else {
        // Windows loopback returns 0 from send() once the kernel UDP send
        // buffer is briefly full (after as few as 2 back-to-back sends).
        // The datagram is NOT queued by the OS — we have to hold it until
        // RawSocketEvent.write fires, then retry. Dart auto-disables write
        // events after each delivery; re-arm so the queue actually drains.
        (_pendingSends[socket] ??= <_PendingSend>[])
            .add(_PendingSend(data, addr, port));
        socket.writeEventsEnabled = true;
      }
    } catch (_) {
      // Network errors are non-fatal in UDP
    }
  }

  void _drainPendingSends(RawDatagramSocket socket) {
    final q = _pendingSends[socket];
    if (q == null || q.isEmpty) return;
    while (q.isNotEmpty) {
      final pkt = q.first;
      final sent = socket.send(pkt.data, pkt.address, pkt.port);
      if (sent == 0) {
        // Buffer still full — leave the queue intact; re-arm write events
        // so we get another notification when room opens up (Dart disables
        // them after each delivery).
        socket.writeEventsEnabled = true;
        return;
      }
      q.removeAt(0);
      if (sent > 0) {
        bytesSent += sent;
        packetsSent++;
      }
    }
    _pendingSends.remove(socket);
  }
}

/// One datagram held over because `RawDatagramSocket.send()` returned 0.
final class _PendingSend {
  final Uint8List data;
  final InternetAddress address;
  final int port;
  _PendingSend(this.data, this.address, this.port);
}
