// ignore_for_file: unawaited_futures
import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import '../core/state_machine.dart';
import '../dtls/state_machine.dart';
import '../ice/state_machine.dart';
import '../rtp/parser.dart';
import '../sctp/state_machine.dart';
import '../srtp/context.dart';
import '../stun/parser.dart';

/// Top-level entry point for the UDP receive isolate.
///
/// Runs a dedicated event loop that only handles socket I/O and timestamping.
/// This eliminates event-loop jitter from SRTP decryption, RTP parsing, and
/// GC pauses in the main isolate — critical for accurate transport-cc
/// timestamps that Chrome's GoogCC uses for bandwidth estimation.
void _udpIsolateEntry(List<dynamic> args) async {
  final sendToMain = args[0] as SendPort;
  final port = args[1] as int;

  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, port);
  final clock = Stopwatch()..start();

  // Receive channel for send requests from main isolate.
  final recvFromMain = ReceivePort();
  // Notify main isolate: ready with our SendPort and actual bound port.
  sendToMain.send(['ready', recvFromMain.sendPort, socket.port]);

  // Handle send requests and close command from main isolate.
  recvFromMain.listen((msg) {
    if (msg is List && msg[0] == 'send') {
      final data = msg[1] as Uint8List;
      final ip = msg[2] as String;
      final destPort = msg[3] as int;
      try {
        final addr = InternetAddress.tryParse(ip);
        if (addr != null && addr.type != InternetAddressType.IPv6) {
          socket.send(data, addr, destPort);
        }
      } catch (_) {}
    } else if (msg == 'close') {
      socket.close();
      recvFromMain.close();
      Isolate.exit();
    }
  });

  // Receive loop — record timestamp immediately on event delivery.
  socket.listen((event) {
    if (event != RawSocketEvent.read) return;
    final timestampUs = clock.elapsedMicroseconds;
    final datagram = socket.receive();
    if (datagram == null) return;
    sendToMain
        .send([datagram.data, timestampUs, datagram.address.address, datagram.port]);
  });
}

/// The only module in webdartc that uses dart:io.
///
/// Owns a UDP socket (via a dedicated [Isolate]) and dispatches incoming
/// packets to the correct state machine. Drives timers on behalf of all
/// protocol modules.
final class TransportController {
  SendPort? _isolateSendPort;
  ReceivePort? _recvPort;
  int _localPort = 0;

  IceStateMachine? _ice;
  DtlsStateMachine? _dtls;
  SrtpContext? _srtp;
  SctpStateMachine? _sctp;

  int get localPort => _localPort;
  String _localAddress = '0.0.0.0';
  String get localAddress => _localAddress;

  final _timers = <String, Timer>{};

  /// Called when an RTP packet is decrypted (SRTP → RTP).
  /// The [int] parameter is the monotonic arrival timestamp in microseconds,
  /// recorded in the receive isolate before any processing delay.
  void Function(Uint8List, int arrivalUs)? onRtp;

  /// Called when an RTCP packet is decrypted (SRTCP → RTCP).
  void Function(Uint8List)? onRtcp;

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /// Bind to a UDP port (in a dedicated isolate) and start receiving packets.
  ///
  /// If [candidateAddress] is provided, it's used as the local address for
  /// ICE candidates (e.g. '127.0.0.1' for loopback testing, or a LAN IP).
  /// If null, auto-detects a suitable local IPv4 address.
  Future<void> start({int port = 0, String? candidateAddress}) async {
    final recvFromIsolate = ReceivePort();
    final completer = Completer<void>();

    await Isolate.spawn(_udpIsolateEntry, [recvFromIsolate.sendPort, port]);

    recvFromIsolate.listen((msg) {
      if (msg is List && msg[0] == 'ready') {
        _isolateSendPort = msg[1] as SendPort;
        _localPort = msg[2] as int;
        completer.complete();
      } else if (msg is List && msg[0] is Uint8List) {
        // Received packet: [data, timestampUs, ip, port]
        _onIsolatePacket(
          msg[0] as Uint8List,
          msg[1] as int,
          msg[2] as String,
          msg[3] as int,
        );
      }
    });

    _recvPort = recvFromIsolate;
    _localAddress = candidateAddress ?? await _findLocalIpv4();
    await completer.future;
  }

  static Future<String> _findLocalIpv4() async {
    // Try to find a non-loopback IPv4 address; fall back to loopback.
    try {
      final interfaces = await NetworkInterface.list(
          type: InternetAddressType.IPv4);
      for (final iface in interfaces) {
        for (final addr in iface.addresses) {
          if (!addr.isLoopback) return addr.address;
        }
      }
    } catch (_) {}
    return '127.0.0.1';
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
    for (final timer in _timers.values) {
      timer.cancel();
    }
    _timers.clear();
    _isolateSendPort?.send('close');
    _isolateSendPort = null;
    _recvPort?.close();
    _recvPort = null;
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

  /// Start the DTLS handshake, sending the initial flight and scheduling
  /// the retransmit timer.  Must be called after ICE reaches connected.
  void startDtlsHandshake({
    required String remoteIp,
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
    _sendUdp(rtpBytes, pair.remote.ip, pair.remote.port);
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
      _sendUdp(sctpBytes, pair.remote.ip, pair.remote.port);
    }
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  // Debug logging — set WEBDARTC_DEBUG=1 env var to trace packet flow.
  static final bool _debug = Platform.environment['WEBDARTC_DEBUG'] == '1';

  /// Called on the main isolate when a packet arrives from the receive isolate.
  void _onIsolatePacket(Uint8List data, int arrivalUs, String remoteIp, int remotePort) {
    if (_debug) {
      stderr.writeln('[transport] RX ${data.length}b from $remoteIp:$remotePort'
          ' b0=${data.isNotEmpty ? data[0].toRadixString(16) : "?"}');
      if (data.isNotEmpty && (data[0] == 0x00 || data[0] == 0x01)) {
        final hex = data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
        stderr.writeln('[transport] RX hex: $hex');
      }
    }

    _dispatch(data, arrivalUs, remoteIp, remotePort);
  }

  void _dispatch(Uint8List data, int arrivalUs, String remoteIp, int remotePort) {
    if (data.isEmpty) return;
    final firstByte = data[0];

    if (StunParser.isStun(data)) {
      _processIce(data, remoteIp, remotePort);
    } else if (firstByte >= 20 && firstByte <= 63) {
      // DTLS record layer
      _processDtls(data, remoteIp, remotePort);
    } else if (firstByte >= 128 && firstByte <= 191) {
      // RTP or RTCP
      _processSrtp(data, arrivalUs, remoteIp, remotePort);
    }
    // Else: unknown — discard
  }

  void _processIce(Uint8List data, String remoteIp, int remotePort) {
    final ice = _ice;
    if (ice == null) return;
    final result = ice.processInput(data, remoteIp: remoteIp, remotePort: remotePort);
    if (result.isOk) {
      _sendOutputPackets(result.value.outputPackets);
      _scheduleTimeout(result.value.nextTimeout, 'ice-check');
    }
  }

  void _processDtls(Uint8List data, String remoteIp, int remotePort) {
    final dtls = _dtls;
    if (dtls == null) return;
    final result = dtls.processInput(data, remoteIp: remoteIp, remotePort: remotePort);
    if (result.isOk) {
      _sendOutputPackets(result.value.outputPackets);
      _scheduleTimeout(result.value.nextTimeout, 'dtls-retransmit');
    }
  }

  void _processSrtp(Uint8List data, int arrivalUs, String remoteIp, int remotePort) {
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

  void _sendOutputPackets(List<OutputPacket> packets) {
    for (final pkt in packets) {
      // If the IP is not a valid address (hostname), resolve it asynchronously.
      if (InternetAddress.tryParse(pkt.remoteIp) == null && !_dnsCache.containsKey(pkt.remoteIp)) {
        _resolveAndSend(pkt);
      } else {
        _sendUdp(pkt.data, pkt.remoteIp, pkt.remotePort);
      }
    }
  }

  Future<void> _resolveAndSend(OutputPacket pkt) async {
    final addr = await _resolveAddress(pkt.remoteIp);
    if (addr != null) {
      _sendUdp(pkt.data, pkt.remoteIp, pkt.remotePort);
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

  void _sendUdp(Uint8List data, String ip, int port) {
    final sendPort = _isolateSendPort;
    if (sendPort == null) return;
    try {
      final addr = InternetAddress.tryParse(ip);
      if (addr == null) {
        // Check DNS cache for hostname (async resolution happens in _sendOutputPackets).
        final cached = _dnsCache[ip];
        if (cached == null) return;
        ip = cached.address;
      } else if (addr.type == InternetAddressType.IPv6) {
        // Skip IPv6 destinations.
        return;
      }
      if (_debug) {
        stderr.writeln('[transport] TX ${data.length}b to $ip:$port'
            ' b0=${data.isNotEmpty ? data[0].toRadixString(16) : "?"}');
        if (data.isNotEmpty && (data[0] == 0x00 || data[0] == 0x01)) {
          final hex = data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
          stderr.writeln('[transport] TX hex: $hex');
        }
      }
      sendPort.send(['send', data, ip, port]);
    } catch (_) {
      // Network errors are non-fatal in UDP
    }
  }

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
      _sendOutputPackets(result.value.outputPackets);
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
    return null;
  }
}
