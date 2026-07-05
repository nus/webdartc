// ignore_for_file: unawaited_futures
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../api/setting_engine.dart';
import '../core/hex.dart';
import '../core/log.dart';
import '../core/state_machine.dart';
import '../dtls/state_machine.dart';
import '../ice/state_machine.dart';
import '../rtp/parser.dart';
import '../sctp/state_machine.dart';
import '../srtp/context.dart';
import '../stun/parser.dart';
import '../turn/channel_data.dart';
import '../turn/state_machine.dart';

part 'packet_demuxer.dart';
part 'socket_pool.dart';
part 'timer_scheduler.dart';
part 'turn_relay_router.dart';

/// The only module in webdartc that uses dart:io.
///
/// Composes the transport machinery — [SocketPool] (bound UDP sockets +
/// send/receive), [PacketDemuxer] (inbound routing to the protocol state
/// machines), [TimerScheduler] (protocol timers), and [TurnRelayRouter]
/// (outbound relay wrapping) — and owns the TURN allocation lifecycle,
/// TURN-TCP control connections, and the DNS cache. Per-IP bind makes ICE
/// replies leave on the same interface that received the request — each
/// socket has a fixed source IP, sidestepping the kernel's source-address
/// selection.
final class TransportController {
  late final SocketPool _pool =
      SocketPool(nowUs: () => _arrivalClock.elapsedMicroseconds)
        ..onDatagram = ((data, arrivalUs, remoteIp, remotePort, bindIp) =>
            _demux.dispatch(data, arrivalUs, remoteIp, remotePort, bindIp))
        ..resolveCached = ((host) => _dnsCache[host])
        ..selectedLocalIp = (() => _ice?.selectedPair?.local.ip);

  late final PacketDemuxer _demux = PacketDemuxer(this);
  late final TurnRelayRouter _relay = TurnRelayRouter(this);
  final TimerScheduler _timers = TimerScheduler();

  IceStateMachine? _ice;
  DtlsStateMachine? _dtls;
  SrtpContext? _srtp;
  SctpStateMachine? _sctp;

  List<TurnServer> _turnServers = const [];

  /// Active allocations keyed by the TURN server's (IP, port). Record
  /// keys give value equality without per-datagram string interpolation
  /// in the dispatch path.
  final Map<(IpAddress, int), TurnAllocation> _allocations = {};

  /// TCP control connections to TURN servers (RFC 5766 §2.1). Keyed by
  /// the same `(serverIp, serverPort)` tuple as [_allocations] so the
  /// send path can pick UDP-raw vs TCP without a second lookup.
  final Map<(IpAddress, int), _TurnTcpConnection> _turnTcpConnections = {};

  TransportController() {
    // Timer routing: each protocol's TimerToken types map to its state
    // machine plus the way its output packets reach the wire.
    _timers._registerRoute(
      const [IceTimerToken, IceConsentToken, IceGatheringTimeoutToken],
      _TimerRoute(
        handle: (t) => _ice?.handleTimeout(t) ?? const Ok(ProcessResult.empty),
        sendOutputs: _sendOutputPackets,
      ),
    );
    _timers._registerRoute(
      const [DtlsRetransmitToken],
      _TimerRoute(
        handle: (t) => _dtls?.handleTimeout(t) ?? const Ok(ProcessResult.empty),
        sendOutputs: _sendOutputPackets,
      ),
    );
    // SCTP timer outputs are raw SCTP packets — they must be encrypted
    // via DTLS before going on the wire (the receive-side dispatch only
    // recognises DTLS records 0x14–0x3F and discards anything else).
    // The receive-path SCTP handler in PeerConnection routes ProcessResult
    // packets through `sendSctp`, but timer-driven retransmits land here
    // and would otherwise bypass DTLS, leaving every T3-rtx attempt to be
    // dropped by the peer.
    _timers._registerRoute(
      const [SctpT1InitToken, SctpT1CookieToken, SctpT3RtxToken],
      _TimerRoute(
        handle: (t) => _sctp?.handleTimeout(t) ?? const Ok(ProcessResult.empty),
        sendOutputs: (pkts) {
          for (final pkt in pkts) {
            sendSctp(pkt.data);
          }
        },
      ),
    );
    // Token doesn't identify its allocation, so broadcast and let each
    // SM ignore tokens that aren't theirs. Output is sent inline so a
    // simultaneous refresh on multiple allocations isn't dropped.
    _timers._registerRoute(
      const [TurnRefreshToken, TurnPermissionRefreshToken,
          TurnChannelRefreshToken],
      _TimerRoute(
        handle: (t) {
          _broadcastTurnTimeout(t);
          return const Ok(ProcessResult.empty);
        },
        sendOutputs: _sendOutputPackets,
      ),
    );
  }

  /// (ip, port) pairs advertised as ICE host candidates.
  List<HostBinding> get bindings => _pool._bindings;

  /// Snapshot of TURN allocations the transport currently owns.
  /// Primarily for tests + diagnostics; membership order isn't part of
  /// the contract.
  List<TurnAllocation> get turnAllocations => _allocations.values.toList();

  /// Monotonically-increasing byte counts spanning every UDP datagram
  /// the transport has put on / taken off the wire, plus everything
  /// pushed through a TURN-TCP / TLS control link. Surfaced via
  /// `PeerConnection.getStats()`.
  int get bytesSent => _pool.bytesSent;
  int get bytesReceived => _pool.bytesReceived;
  int get packetsSent => _pool.packetsSent;
  int get packetsReceived => _pool.packetsReceived;

  /// First advertised IP, in canonical text form. Used by the legacy
  /// single-IP SDP builder path.
  String get localAddress =>
      bindings.isEmpty ? '0.0.0.0' : bindings.first.ip.toCanonical();

  /// First advertised port. Used by the legacy single-IP SDP builder path.
  int get localPort => bindings.isEmpty ? 0 : bindings.first.port;

  /// Monotonic clock for transport-cc arrival timestamps.  Stopwatch uses
  /// clock_gettime(CLOCK_MONOTONIC) — immune to NTP adjustments and wall-
  /// clock jumps that DateTime.now() is subject to.
  final Stopwatch _arrivalClock = Stopwatch()..start();

  /// Current value of the monotonic arrival clock in microseconds. Shares the
  /// clock used for `onRtp`'s `arrivalUs`, so the receive path can compare
  /// packet arrival times against "now" (e.g. for jitter-buffer playout).
  int get nowUs => _arrivalClock.elapsedMicroseconds;

  /// Called when an RTP packet is decrypted (SRTP → RTP).
  /// The [int] parameter is the monotonic arrival timestamp in microseconds.
  void Function(Uint8List, int arrivalUs)? onRtp;

  /// Called when an RTCP packet is decrypted (SRTCP → RTCP).
  void Function(Uint8List)? onRtcp;

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /// Bind UDP sockets and start receiving packets, then kick off TURN
  /// allocations against the registered servers.
  Future<void> start({
    SettingEngine settingEngine = const SettingEngine(),
    int port = 0,
  }) async {
    await _pool.bind(settingEngine: settingEngine, port: port);
    _startTurnAllocations(settingEngine);
  }

  /// Forward a ProcessResult produced by an ICE control action (e.g.
  /// setRemoteParameters, addRemoteCandidate) to the transport so that
  /// the initial STUN binding requests and their retransmit timers are sent.
  void handleIceControl(Result<ProcessResult, ProtocolError> result) {
    if (!result.isOk) return;
    _sendOutputPackets(result.value.outputPackets);
    _timers.schedule(result.value.nextTimeout, 'ice-init');
  }

  Future<void> stop() async {
    _pool._stopped = true;
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
    _relay._clear();
    for (final conn in _turnTcpConnections.values) {
      conn.close();
    }
    _turnTcpConnections.clear();
    _timers.cancelAll();
    _pool.close();
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

  // ── TURN allocation lifecycle ─────────────────────────────────────────────

  void _startTurnAllocations(SettingEngine settingEngine) {
    if (_turnServers.isEmpty || bindings.isEmpty) return;
    final host = bindings.first;
    for (final server in _turnServers) {
      switch (server.transport) {
        case 'udp':
          if (server.secure) {
            // RFC 7350 defines DTLS-over-UDP TURN (`turns:?transport=udp`).
            // Not implemented yet; skip rather than allocate against a
            // server we can't actually talk to.
            continue;
          }
          _startUdpAllocation(server, host);
        case 'tcp':
          // Fire-and-forget: Socket.connect is async but we don't want
          // to block sibling allocations on a slow server. Failures log
          // and skip; the missing relay candidate is simply absent from
          // ICE's pool.
          unawaited(_startTcpAllocation(
              server, host, settingEngine.onBadTurnCertificate));
      }
    }
  }

  void _startUdpAllocation(TurnServer server, HostBinding host) {
    final serverIp = IpAddress.parse(server.host);
    final allocation =
        _buildAllocation(server, host, serverIp, padChannelData: false);
    _allocations[(serverIp, server.port)] = allocation;
    final res = allocation.start();
    if (res.isOk) {
      _sendOutputPackets(res.value.outputPackets);
      _timers.schedule(
          res.value.nextTimeout, 'turn-${server.host}:${server.port}');
    }
  }

  Future<void> _startTcpAllocation(
      TurnServer server,
      HostBinding host,
      bool Function(X509Certificate)? onBadCertificate) async {
    // Connect first; pass the original `server.host` string so both
    // plain TCP and TLS see the same hostname (TLS needs it for SNI +
    // certificate validation). The kernel resolves it for us — we
    // learn the chosen IP from `socket.remoteAddress` afterwards.
    // ignore: close_sinks  — ownership transfers to _TurnTcpConnection.
    final Socket socket;
    try {
      socket = server.secure
          ? await SecureSocket.connect(
              server.host,
              server.port,
              onBadCertificate: onBadCertificate,
            )
          : await Socket.connect(server.host, server.port);
    } catch (e) {
      if (_debug) {
        webdartcLog(
            '[transport] TURN-${server.secure ? "TLS" : "TCP"} connect'
            ' ${server.host}:${server.port} failed: $e');
      }
      return;
    }

    final serverIp = IpAddress.fromBytes(socket.remoteAddress.rawAddress);
    // Cache the hostname → InternetAddress mapping the kernel just
    // resolved so any subsequent UDP send to the same host (e.g. a
    // second `iceServers` entry or an unrelated STUN URI) skips its
    // own DNS lookup.
    _dnsCache[server.host] = socket.remoteAddress;
    final endpoint = (serverIp, server.port);
    final allocation =
        _buildAllocation(server, host, serverIp, padChannelData: true);
    final conn = _TurnTcpConnection(
      socket,
      onFrame: (frame) {
        // Dispatch each demuxed STUN/ChannelData frame through the
        // same allocation lookup the UDP receive path uses.
        _demux.dispatch(frame, _arrivalClock.elapsedMicroseconds, serverIp,
            server.port, host.ip);
      },
      onClose: () {
        _turnTcpConnections.remove(endpoint);
        // The allocation entry stays in `_allocations` long enough
        // for the upper layers to observe `state != allocated`; an
        // explicit ICE candidate teardown isn't wired yet.
      },
      // TLS path: byte counts are post-TLS plaintext. Packet count is
      // approximate — one per `send` on transmit, one per TCP chunk
      // on receive. Good enough for the stats.
      onBytesSent: (bytes) {
        _pool.bytesSent += bytes;
        _pool.packetsSent++;
      },
      onBytesReceived: (bytes) {
        _pool.bytesReceived += bytes;
        _pool.packetsReceived++;
      },
    );

    _allocations[endpoint] = allocation;
    _turnTcpConnections[endpoint] = conn;
    final res = allocation.start();
    if (res.isOk) {
      _sendOutputPackets(res.value.outputPackets);
      _timers.schedule(
          res.value.nextTimeout, 'turn-${server.host}:${server.port}');
    }
  }

  TurnAllocation _buildAllocation(TurnServer server, HostBinding host,
      IpAddress serverIp, {required bool padChannelData}) {
    final allocation = TurnAllocation(
      serverIp: serverIp,
      serverPort: server.port,
      username: server.username,
      password: server.password,
      padChannelData: padChannelData,
    );
    allocation.onAllocated = (relayedIp, relayedPort) {
      _relay._relayedAllocations[relayedIp] = allocation;
      final res = _ice?.addLocalRelayCandidate(
        relayedIp: relayedIp,
        relayedPort: relayedPort,
        relatedAddress: host.ip,
        relatedPort: host.port,
      );
      if (res != null && res.isOk) {
        _sendOutputPackets(res.value.outputPackets);
        _timers.schedule(res.value.nextTimeout, 'ice-check');
      }
    };
    allocation.onPeerData = (peerIp, peerPort, payload) {
      // Re-dispatch as if direct from the peer so upper layers don't
      // need to know it came via TURN. Loop-safe: `peerIp` ≠ TURN
      // server, so the next `_allocations[(peerIp, peerPort)]` misses.
      final relayedIp = allocation.relayedAddress;
      if (relayedIp == null) return;
      _demux.dispatch(payload, _arrivalClock.elapsedMicroseconds, peerIp,
          peerPort, relayedIp);
    };
    allocation.onPermissionResult = (peerIp, _) {
      _relay._pendingPermissions.remove((allocation, peerIp));
    };
    allocation.onChannelResult = (channel, peerIp, peerPort, bound) {
      final key = (allocation, peerIp, peerPort);
      _relay._pendingChannelBinds.remove(key);
      if (bound) {
        // Channel is bound; `wrapSend` will pick ChannelData from now
        // on. The counter has done its job — drop it so long-running
        // calls with peer churn don't accumulate dead entries.
        _relay._peerSendCounts.remove(key);
      } else {
        // Server refused to bind this peer (rare: 486 quota, 437 alloc
        // mismatch, etc.). Freeze the counter so we don't keep
        // retrying forever; future sends stay on the heavier
        // Send-indication path.
        _relay._peerSendCounts[key] = TurnRelayRouter._channelBindFrozen;
      }
    };
    return allocation;
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
      _timers.schedule(result.value.nextTimeout, 'dtls-retransmit');
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
        _timers.schedule(result.value.nextTimeout, 'dtls-app');
      }
    } else {
      _sendUdp(sctpBytes, pair.remote.ip.toCanonical(), pair.remote.port,
          localIp: pair.local.ip);
    }
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  // Debug logging — set WEBDARTC_DEBUG=1 env var to trace packet flow.
  static final bool _debug = webdartcDebug;

  /// Sends each packet as a raw UDP datagram. Callers must pass packets
  /// whose [OutputPacket.data] is already wire-ready — STUN messages,
  /// DTLS records, or DTLS-encrypted application data. SCTP state-machine
  /// output is plaintext SCTP and must go through [sendSctp] instead, which
  /// applies the DTLS encryption layer first.
  void _sendOutputPackets(List<OutputPacket> packets) {
    for (final pkt in packets) {
      // TURN-TCP control link short-circuits the UDP send path before
      // hostname resolution — the connection was set up against a
      // numeric address at allocation time, so `pkt.remoteIp` here is
      // already canonical.
      final tcp = _lookupTurnTcp(pkt.remoteIp, pkt.remotePort);
      if (tcp != null) {
        tcp.send(pkt.data);
        continue;
      }
      // If the IP is not a valid address (hostname), resolve it asynchronously.
      if (InternetAddress.tryParse(pkt.remoteIp) == null && !_dnsCache.containsKey(pkt.remoteIp)) {
        _resolveAndSend(pkt);
      } else {
        _sendUdp(pkt.data, pkt.remoteIp, pkt.remotePort, localIp: pkt.localIp);
      }
    }
  }

  _TurnTcpConnection? _lookupTurnTcp(String ip, int port) {
    if (_turnTcpConnections.isEmpty) return null;
    final parsed = IpAddress.tryParse(ip);
    if (parsed == null) return null;
    return _turnTcpConnections[(parsed, port)];
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

  /// Send [data] to `ip:port`, wrapping through a TURN relay when ICE has
  /// nominated a relayed path for this source.
  void _sendUdp(Uint8List data, String ip, int port, {IpAddress? localIp}) {
    if (_relay._hasRelays) {
      final allocation = _relay._selectRelayAllocation(localIp);
      if (allocation != null) {
        final peer = IpAddress.tryParse(ip);
        // Skip the wrap when the destination is itself a TURN server we
        // own an allocation against — that's a TURN-internal send
        // (Allocate / Refresh / CreatePermission / ChannelBind) and
        // re-wrapping would loop instead of reaching the server.
        if (peer != null && !_allocations.containsKey((peer, port))) {
          _relay._sendViaRelay(allocation, peer, port, data);
          return;
        }
      }
    }
    _pool.sendRaw(data, ip, port, localIp: localIp);
  }

  // ── Timers ────────────────────────────────────────────────────────────────

  /// Public hook so PeerConnection can schedule SCTP-layer timers
  /// (T3-rtx, T1-init, T1-cookie) returned from `_sctp.sendData()` /
  /// `_sctp.openDataChannel()`. Without this, lost SCTP DATA chunks
  /// would never trigger retransmission because the per-chunk T3-rtx
  /// `nextTimeout` returned by the SCTP state machine was being
  /// discarded by the DataChannel send callback in peer_connection.dart.
  void scheduleSctpTimeout(Timeout? timeout) =>
      _timers.schedule(timeout, 'sctp');

  void _broadcastTurnTimeout(TimerToken token) {
    for (final entry in _allocations.entries) {
      final res = entry.value.handleTimeout(token);
      if (res.isOk && res.value.outputPackets.isNotEmpty) {
        _sendOutputPackets(res.value.outputPackets);
        _timers.schedule(
            res.value.nextTimeout, 'turn-${entry.key.$1}:${entry.key.$2}');
      }
    }
  }
}

/// TCP control connection to a single TURN server (RFC 5766 §2.1).
///
/// STUN messages and ChannelData frames have self-describing length
/// fields, so the wire is just a stream of those frames back-to-back
/// (RFC 5766 §11.5 requires ChannelData to be padded to a 4-byte
/// boundary on TCP so the next frame stays aligned). [onFrame] fires
/// once per complete frame extracted from the receive buffer.
final class _TurnTcpConnection {
  final Socket _socket;
  final void Function(Uint8List frame) onFrame;
  final void Function() onClose;

  /// Per-`send` callback: feeds the outer transport's `bytesSent` /
  /// `packetsSent` counters. Post-TLS-decrypt bytes (one frame per
  /// call). Decoupled from [onBytesReceived] so neither path carries
  /// a dead-zero argument.
  final void Function(int bytes) onBytesSent;

  /// Per-chunk callback: one invocation per TCP read of decrypted
  /// bytes off the wire.
  final void Function(int bytes) onBytesReceived;

  Uint8List _buffer = Uint8List(0);
  bool _closed = false;

  /// Wrap an already-connected [socket] (plain TCP or TLS-over-TCP —
  /// `SecureSocket` extends [Socket] so the same demux applies). The
  /// caller is responsible for the actual `Socket.connect` /
  /// `SecureSocket.connect` so it can pass through TLS-specific knobs
  /// without leaking them into this class.
  _TurnTcpConnection(this._socket,
      {required this.onFrame,
      required this.onClose,
      required this.onBytesSent,
      required this.onBytesReceived}) {
    // STUN retransmits over TCP are managed by the protocol layer; the
    // 200 ms Nagle delay just inflates handshake RTT.
    _socket.setOption(SocketOption.tcpNoDelay, true);
    _socket.listen(_onBytes, onError: _onError, onDone: _onDone);
  }

  InternetAddress get remoteAddress => _socket.remoteAddress;

  void send(Uint8List data) {
    if (_closed) return;
    _socket.add(data);
    onBytesSent(data.length);
  }

  void close() {
    if (_closed) return;
    _closed = true;
    _socket.destroy();
  }

  void _onBytes(Uint8List chunk) {
    onBytesReceived(chunk.length);
    if (_buffer.isEmpty) {
      _buffer = Uint8List.fromList(chunk);
    } else {
      final next = Uint8List(_buffer.length + chunk.length)
        ..setRange(0, _buffer.length, _buffer)
        ..setRange(_buffer.length, _buffer.length + chunk.length, chunk);
      _buffer = next;
    }
    _drain();
  }

  void _drain() {
    while (true) {
      final next = turnTcpFrameLength(_buffer);
      switch (next) {
        case TurnTcpFrameLengthNeedMore():
          return;
        case TurnTcpFrameLengthMalformed():
          // The server got out of sync with framing. Close so the upper
          // layer can rebuild the allocation if it cares.
          _onError('TURN-TCP: out-of-band byte 0x${_buffer[0].toRadixString(16)}');
          return;
        case TurnTcpFrameLengthKnown(:final totalBytes):
          if (_buffer.length < totalBytes) return;
          onFrame(Uint8List.sublistView(_buffer, 0, totalBytes));
          _buffer = _buffer.length == totalBytes
              ? Uint8List(0)
              : Uint8List.fromList(
                  Uint8List.sublistView(_buffer, totalBytes));
      }
    }
  }

  void _onError(Object err, [StackTrace? st]) {
    if (_closed) return;
    _closed = true;
    _socket.destroy();
    onClose();
  }

  void _onDone() {
    if (_closed) return;
    _closed = true;
    onClose();
  }
}
