part of 'peer_connection.dart';

/// Event emitted when a new local ICE candidate is available.
final class PeerConnectionIceEvent {
  final String candidate; // SDP a=candidate line
  final String sdpMid;
  final int sdpMLineIndex;

  const PeerConnectionIceEvent({
    required this.candidate,
    required this.sdpMid,
    required this.sdpMLineIndex,
  });
}

/// Event emitted when a remote data channel is opened.
final class DataChannelEvent {
  final DataChannel channel;
  const DataChannelEvent(this.channel);
}

/// Event emitted when a remote media track is received.
final class TrackEvent {
  final String kind; // "audio" or "video"
  final int ssrc;
  final RtpReceiver receiver;

  /// W3C: The MediaStreamTrack associated with this event (nullable until
  /// a codec backend is registered and decoding is active).
  final MediaStreamTrack? track;

  /// W3C: The MediaStreams associated with this track.
  final List<MediaStream> streams;

  const TrackEvent({
    required this.kind,
    required this.ssrc,
    required this.receiver,
    this.track,
    this.streams = const [],
  });
}

/// RTP receiver — receives media RTP packets from a remote peer.
///
/// Obtained from [TrackEvent.receiver] when [PeerConnection.onTrack] fires.
/// For video, a PLI is sent on track creation to request a fresh keyframe.
final class RtpReceiver {
  final String kind;
  final int ssrc;
  final _controller = StreamController<RtpPacket>.broadcast();

  /// W3C: The MediaStreamTrack produced by this receiver (nullable until
  /// a codec backend is registered).
  MediaStreamTrack? _track;
  MediaStreamTrack? get track => _track;

  /// W3C RTP Transport: The RtpPacketReceiver for low-level access.
  RtpPacketReceiver? _packetReceiver;

  RtpReceiver._({required this.kind, required this.ssrc});

  /// W3C RTP Transport: Get an RtpPacketReceiver for direct packet access.
  Future<RtpPacketReceiver> replacePacketReceiver() async {
    _packetReceiver ??= RtpPacketReceiver(mid: null, ssrcs: [ssrc]);
    return _packetReceiver!;
  }

  /// Stream of received RTP packets for this track.
  Stream<RtpPacket> get onRtp => _controller.stream;

  void _deliver(RtpPacket packet) {
    _packetReceiver?.deliverPacket(packet);
    _controller.add(packet);
  }

  void _close() => _controller.close();
}

/// ICE connection state.
enum IceConnectionState {
  iceNew,
  checking,
  connected,
  completed,
  failed,
  disconnected,
  closed,
}

/// PeerConnection signaling state.
enum SignalingState {
  stable,
  haveLocalOffer,
  haveRemoteOffer,
  haveLocalPrAnswer,
  haveRemotePrAnswer,
  closed,
}

/// PeerConnection connection state.
enum PeerConnectionState {
  closed,
  failed,
  disconnected,
  connecting,
  connected,
}

/// DTLS transport state.
enum DtlsTransportState {
  closed,
  connecting,
  connected,
  failed,
}

/// RTP sender — sends media RTP packets via SRTP.
///
/// Obtained via [PeerConnection.addTrack] or from a transceiver.
final class RtpSender {
  final String kind;
  final int ssrc;
  int payloadType;
  final int clockRate;
  int _sequenceNumber = 0;
  int _timestamp = 0;
  void Function(Uint8List srtpPacket)? _sendCallback;

  /// MID value and extension ID for BUNDLE demux (set by PeerConnection).
  String? _mid;
  int _midExtId = 0;

  /// Send statistics for RTCP SR.
  int _packetsSent = 0;
  int _octetsSent = 0;
  int _lastRtpTimestamp = 0;

  /// W3C: The MediaStreamTrack attached to this sender.
  MediaStreamTrack? _track;
  MediaStreamTrack? get track => _track;

  /// W3C RTP Transport: The RtpPacketSender for low-level access.
  RtpPacketSender? _packetSender;

  RtpSender._({
    required this.kind,
    required this.ssrc,
    required this.payloadType,
    required this.clockRate,
  }) {
    _sequenceNumber = Csprng.randomUint32() & 0xFFFF;
    _timestamp = Csprng.randomUint32();
  }

  /// W3C: Replace the current track with a new one (or null to detach).
  Future<void> replaceTrack(MediaStreamTrack? withTrack) async {
    _track = withTrack;
  }

  /// W3C RTP Transport: Get an RtpPacketSender for direct packet sending.
  ///
  /// Packets sent via [RtpPacketSender.sendRtp] are routed through this
  /// sender's SRTP encryption, sequence numbering, and MID header extension.
  Future<RtpPacketSender> replacePacketSender() async {
    _packetSender ??= RtpPacketSender(
      mid: _mid,
      ssrc: ssrc,
      rtxSsrc: null,
      sendFn: (RtpPacket packet) {
        // Route through RtpSender.sendRtp for proper seq/MID/SRTP handling.
        sendRtp(packet.payload, marker: packet.marker, timestamp: packet.timestamp);
      },
    );
    return _packetSender!;
  }

  /// Send raw RTP payload (codec-encoded data, e.g. Opus frame or VP8 frame).
  ///
  /// The payload is wrapped in an RTP header, SRTP-encrypted, and sent.
  /// [marker] should be true for the first packet of a talkspurt (audio) or
  /// the last packet of a video frame.
  /// Send raw RTP payload.
  ///
  /// If [timestamp] is provided, it is used directly (for reflect/echo).
  /// Otherwise, timestamp is auto-incremented.
  void sendRtp(Uint8List payload, {bool marker = false, int? timestamp, int? timestampIncrement}) {
    if (timestamp != null) {
      _timestamp = timestamp;
    } else {
      final increment = timestampIncrement ?? (kind == 'audio' ? 960 : 3000);
      _timestamp = (_timestamp + increment) & 0xFFFFFFFF;
    }

    // Build one-byte header extension with MID for BUNDLE demux (RFC 8843).
    RtpExtension? ext;
    if (_mid != null && _midExtId > 0) {
      final midBytes = Uint8List.fromList(_mid!.codeUnits);
      // One-byte format: id(4 bits) | len-1(4 bits) | data
      final elemLen = 1 + midBytes.length; // header byte + data
      final padded = (elemLen + 3) & ~3; // pad to 4 bytes
      final extData = Uint8List(padded);
      extData[0] = (_midExtId << 4) | ((midBytes.length - 1) & 0x0F);
      extData.setRange(1, 1 + midBytes.length, midBytes);
      ext = RtpExtension(profile: 0xBEDE, data: extData);
    }

    final rtp = RtpPacket(
      payloadType: payloadType,
      sequenceNumber: _sequenceNumber & 0xFFFF,
      timestamp: _timestamp,
      ssrc: ssrc,
      marker: marker,
      extension: ext != null,
      headerExtension: ext,
      payload: payload,
    );
    _sequenceNumber = (_sequenceNumber + 1) & 0xFFFF;
    _packetsSent++;
    _octetsSent += payload.length;
    _lastRtpTimestamp = _timestamp;
    _sendCallback?.call(rtp.build());
  }
}
