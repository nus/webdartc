/// W3C RTP Transport API types.
/// https://w3c.github.io/webrtc-rtptransport/
library;

import 'dart:async';
import 'dart:typed_data';

import 'packet.dart';

// ── RtpHeaderExtension ──────────────────────────────────────────────────────

/// W3C RTCRtpHeaderExtension — a parsed RTP header extension.
final class RtpHeaderExtension {
  final String uri;
  final Uint8List value;

  const RtpHeaderExtension({required this.uri, required this.value});
}

// ── RtpSendResult ───────────────────────────────────────────────────────────

/// Result of RtpPacketSender.sendRtp().
final class RtpSendResult {
  final RtpSent? sent;
  final RtpUnsentReason? unsent;

  const RtpSendResult({this.sent, this.unsent});

  bool get wasSent => sent != null;
}

/// Confirmation that an RTP packet was sent.
final class RtpSent {
  final double time;
  final int? ackId;
  final int size;

  const RtpSent({required this.time, this.ackId, required this.size});
}

/// Reason an RTP packet was not sent.
enum RtpUnsentReason { overuse, transportUnavailable }

// ── RtpPacketSender ─────────────────────────────────────────────────────────

/// W3C RTCRtpPacketSender — direct RTP packet sending.
/// https://w3c.github.io/webrtc-rtptransport/#rtcrtppacketsender
///
/// Obtained via `RtpSender.replacePacketSender()`.
final class RtpPacketSender {
  final String? mid;
  final int ssrc;
  final int? rtxSsrc;

  final void Function(RtpPacket packet) _sendFn;
  final List<RtpPacket> _packetizedQueue = [];
  final _packetizedController = StreamController<void>.broadcast();

  RtpPacketSender({
    required this.mid,
    required this.ssrc,
    required this.rtxSsrc,
    required void Function(RtpPacket) sendFn,
  }) : _sendFn = sendFn;

  /// Read packetized RTP packets from the internal encoder pipeline.
  List<RtpPacket> readPacketizedRtp(int maxNumberOfPackets) {
    final count = maxNumberOfPackets.clamp(0, _packetizedQueue.length);
    final result = _packetizedQueue.sublist(0, count);
    _packetizedQueue.removeRange(0, count);
    return result;
  }

  /// Event fired when packetized RTP is available.
  Stream<void> get onPacketizedRtp => _packetizedController.stream;

  /// Send an RTP packet directly.
  RtpSendResult sendRtp(RtpPacket packet) {
    try {
      _sendFn(packet);
      return RtpSendResult(
        sent: RtpSent(
          time: DateTime.now().microsecondsSinceEpoch / 1e6,
          size: packet.payload.length,
        ),
      );
    } catch (_) {
      return const RtpSendResult(unsent: RtpUnsentReason.transportUnavailable);
    }
  }

  /// Allocated bandwidth in bits per second (0 if unknown).
  int get allocatedBandwidth => 0;

  /// Internal: enqueue a packetized RTP packet from the encoder pipeline.
  void enqueuePacketized(RtpPacket packet) {
    _packetizedQueue.add(packet);
    _packetizedController.add(null);
  }
}

// ── RtpPacketReceiver ───────────────────────────────────────────────────────

/// W3C RTCRtpPacketReceiver — direct RTP packet receiving.
/// https://w3c.github.io/webrtc-rtptransport/#rtcrtppacketreceiver
///
/// Obtained via `RtpReceiver.replacePacketReceiver()`.
final class RtpPacketReceiver {
  final String? mid;
  final List<int> _ssrcs;

  final List<RtpPacket> _receivedQueue = [];
  final _receivedController = StreamController<void>();

  RtpPacketReceiver({
    required this.mid,
    required List<int> ssrcs,
  }) : _ssrcs = List.unmodifiable(ssrcs);

  List<int> getSsrcs() => _ssrcs;

  /// Read received RTP packets.
  List<RtpPacket> readReceivedRtp(int maxNumberOfPackets) {
    final count = maxNumberOfPackets.clamp(0, _receivedQueue.length);
    final result = _receivedQueue.sublist(0, count);
    _receivedQueue.removeRange(0, count);
    return result;
  }

  /// Event fired when new RTP packets are received.
  Stream<void> get onReceivedRtp => _receivedController.stream;

  /// Internal: deliver a received RTP packet.
  void deliverPacket(RtpPacket packet) {
    _receivedQueue.add(packet);
    _receivedController.add(null);
  }
}

// ── RtpTransport ────────────────────────────────────────────────────────────

/// W3C RTCRtpTransport — transport-level bandwidth information.
/// https://w3c.github.io/webrtc-rtptransport/#rtcrtptransport
final class RtpTransport {
  /// Estimated available bandwidth in bits per second.
  int bandwidthEstimate = 0;

  /// Currently allocated bandwidth in bits per second.
  int allocatedBandwidth = 0;

  /// User-specified maximum bandwidth (0 = no limit).
  int customMaxBandwidth = 0;
}
