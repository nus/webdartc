/// Bidirectional UDP proxy with configurable network impairment.
///
/// Sits between two WebRTC peers, forwarding UDP packets with optional
/// packet loss, delay, jitter, and bandwidth limiting.
///
/// Architecture (single socket):
///
///   Both peers' ICE candidates are rewritten to the proxy's port P.
///   Peer A sends to P → proxy identifies sender by source port → forwards to Peer B.
///   Peer B sends to P → proxy identifies sender by source port → forwards to Peer A.
///   Both peers see a consistent remote address (port P).
library;

import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

/// Network impairment configuration.
final class ImpairmentConfig {
  /// Packet loss rate (0.0 = no loss, 1.0 = drop all).
  final double lossRate;

  /// Fixed delay added to every packet, in milliseconds.
  final int delayMs;

  /// Random jitter range in milliseconds. Actual jitter is ±jitterMs.
  final int jitterMs;

  /// Bandwidth limit in bytes per second. Null = unlimited.
  final int? bandwidthBytesPerSec;

  const ImpairmentConfig({
    this.lossRate = 0.0,
    this.delayMs = 0,
    this.jitterMs = 0,
    this.bandwidthBytesPerSec,
  });

  @override
  String toString() =>
      'ImpairmentConfig(loss=${(lossRate * 100).toStringAsFixed(1)}%, '
      'delay=${delayMs}ms, jitter=±${jitterMs}ms'
      '${bandwidthBytesPerSec != null ? ', bw=${bandwidthBytesPerSec}B/s' : ''})';
}

/// Statistics collected by the proxy.
final class ProxyStats {
  int packetsForwarded = 0;
  int packetsDropped = 0;
  int bytesForwarded = 0;

  @override
  String toString() =>
      'ProxyStats(fwd=$packetsForwarded, drop=$packetsDropped, '
      'bytes=$bytesForwarded)';
}

/// A bidirectional UDP proxy for network impairment testing.
final class UdpProxy {
  final RawDatagramSocket _socket;

  /// The single proxy port. Both peers' candidates are rewritten to this.
  int get port => _socket.port;

  /// For API compatibility with signaling server (both return same port).
  int get port1 => _socket.port;
  int get port2 => _socket.port;

  /// Impairment applied to A→B packets.
  ImpairmentConfig impairmentAtoB;

  /// Impairment applied to B→A packets.
  ImpairmentConfig impairmentBtoA;

  final ProxyStats statsAtoB = ProxyStats();
  final ProxyStats statsBtoA = ProxyStats();

  // Real peer ports — set by signaling server when rewriting candidates.
  // A peer may have multiple ports (one per network interface).
  final Set<int> _portsA = {};
  final Set<int> _portsB = {};
  // Primary address used to forward packets TO each peer.
  InternetAddress? _fwdAddrA;
  int? _fwdPortA;
  InternetAddress? _fwdAddrB;
  int? _fwdPortB;

  /// Debug description of real peer addresses.
  String get debugInfo =>
      'P=${_socket.port} '
      'portsA=$_portsA fwdA=${_fwdAddrA?.address}:$_fwdPortA '
      'portsB=$_portsB fwdB=${_fwdAddrB?.address}:$_fwdPortB';

  final Random _random = Random();
  _TokenBucket? _bucketAtoB;
  _TokenBucket? _bucketBtoA;

  bool _closed = false;

  UdpProxy._(
    this._socket, {
    this.impairmentAtoB = const ImpairmentConfig(),
    this.impairmentBtoA = const ImpairmentConfig(),
  }) {
    _socket.listen(_onReceive);
    if (impairmentAtoB.bandwidthBytesPerSec != null) {
      _bucketAtoB = _TokenBucket(impairmentAtoB.bandwidthBytesPerSec!);
    }
    if (impairmentBtoA.bandwidthBytesPerSec != null) {
      _bucketBtoA = _TokenBucket(impairmentBtoA.bandwidthBytesPerSec!);
    }
  }

  /// Start a proxy bound on loopback.
  static Future<UdpProxy> start({
    ImpairmentConfig impairmentAtoB = const ImpairmentConfig(),
    ImpairmentConfig impairmentBtoA = const ImpairmentConfig(),
  }) async {
    final s = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
    return UdpProxy._(s,
        impairmentAtoB: impairmentAtoB, impairmentBtoA: impairmentBtoA);
  }

  /// Start with symmetric impairment (same config both directions).
  static Future<UdpProxy> startSymmetric({
    ImpairmentConfig impairment = const ImpairmentConfig(),
  }) async {
    return start(impairmentAtoB: impairment, impairmentBtoA: impairment);
  }

  /// Register a real address/port for Peer A (called by signaling server).
  void setRealAddressA(InternetAddress addr, int port) {
    _portsA.add(port);
    _fwdAddrA ??= addr;
    _fwdPortA ??= port;
  }

  /// Register a real address/port for Peer B (called by signaling server).
  void setRealAddressB(InternetAddress addr, int port) {
    _portsB.add(port);
    _fwdAddrB ??= addr;
    _fwdPortB ??= port;
  }

  void _onReceive(RawSocketEvent event) {
    if (event != RawSocketEvent.read || _closed) return;
    final dg = _socket.receive();
    if (dg == null) return;

    final srcPort = dg.port;

    // Identify sender by source port and forward to the other peer.
    // Update forward target dynamically — the reply goes to the address
    // that last sent us a packet.
    if (_portsA.contains(srcPort)) {
      _fwdAddrA = dg.address;
      _fwdPortA = srcPort;
      if (_fwdPortB == null) return;
      _forward(dg.data, _fwdAddrB!, _fwdPortB!, impairmentAtoB, statsAtoB,
          _bucketAtoB);
    } else if (_portsB.contains(srcPort)) {
      _fwdAddrB = dg.address;
      _fwdPortB = srcPort;
      if (_fwdPortA == null) return;
      _forward(dg.data, _fwdAddrA!, _fwdPortA!, impairmentBtoA, statsBtoA,
          _bucketBtoA);
    }
    // Unknown source — ignore (might be before addresses are configured).
  }

  void _forward(
    Uint8List data,
    InternetAddress destAddr,
    int destPort,
    ImpairmentConfig config,
    ProxyStats stats,
    _TokenBucket? bucket,
  ) {
    // Packet loss.
    if (config.lossRate > 0 && _random.nextDouble() < config.lossRate) {
      stats.packetsDropped++;
      return;
    }

    // Bandwidth limit.
    if (bucket != null && !bucket.tryConsume(data.length)) {
      stats.packetsDropped++;
      return;
    }

    // Delay + jitter.
    final totalDelay = _computeDelay(config);
    if (totalDelay > 0) {
      Timer(Duration(milliseconds: totalDelay), () {
        if (!_closed) {
          _socket.send(data, destAddr, destPort);
          stats.packetsForwarded++;
          stats.bytesForwarded += data.length;
        }
      });
    } else {
      _socket.send(data, destAddr, destPort);
      stats.packetsForwarded++;
      stats.bytesForwarded += data.length;
    }
  }

  int _computeDelay(ImpairmentConfig config) {
    var delay = config.delayMs;
    if (config.jitterMs > 0) {
      delay += _random.nextInt(config.jitterMs * 2 + 1) - config.jitterMs;
    }
    return delay < 0 ? 0 : delay;
  }

  Future<void> close() async {
    _closed = true;
    _socket.close();
  }
}

/// Simple token bucket for bandwidth limiting.
final class _TokenBucket {
  final int bytesPerSecond;
  double _tokens;
  DateTime _lastRefill;

  _TokenBucket(this.bytesPerSecond)
      : _tokens = bytesPerSecond.toDouble(),
        _lastRefill = DateTime.now();

  bool tryConsume(int bytes) {
    _refill();
    if (_tokens >= bytes) {
      _tokens -= bytes;
      return true;
    }
    return false;
  }

  void _refill() {
    final now = DateTime.now();
    final elapsed = now.difference(_lastRefill).inMicroseconds / 1000000.0;
    _tokens = min(_tokens + elapsed * bytesPerSecond, bytesPerSecond * 2.0);
    _lastRefill = now;
  }
}
