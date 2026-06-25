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
///
/// When the negotiated codec has both a registered decoder backend and an RTP
/// depacketizer, the receiver exposes a decoded-media [track]: subscribing to
/// `track.onVideoFrame` / `track.onAudioData` lazily spins up a
/// jitter-buffer → depacketize → decode pipeline (the W3C receive path). The
/// raw [onRtp] stream is always available regardless, as a low-level escape
/// hatch independent of codec registration.
///
/// For video, a PLI is sent on track creation (and retransmitted until the
/// first keyframe decodes) to request a fresh keyframe.
final class RtpReceiver {
  final String kind;
  final int ssrc;
  final _controller = StreamController<RtpPacket>.broadcast();

  /// Decode pipeline (jitter → depacketize → decode → track), or null when the
  /// negotiated codec has no registered decoder + depacketizer — in that case
  /// [track] is null and consumers use the raw [onRtp] stream.
  final ReceivePipeline? _pipeline;

  /// W3C: The MediaStreamTrack produced by this receiver. Non-null when the
  /// codec has a registered decoder + depacketizer; null otherwise (use
  /// [onRtp] for low-level access in that case).
  MediaStreamTrack? get track => _pipeline?.track;

  /// W3C RTP Transport: The RtpPacketReceiver for low-level access.
  RtpPacketReceiver? _packetReceiver;

  RtpReceiver._({
    required this.kind,
    required this.ssrc,
    String? codecKey,
    int clockRate = 0,
    int channels = 2,
    void Function()? requestKeyframe,
  }) : _pipeline = codecKey == null
            ? null
            : ReceivePipeline.tryCreate(
                kind: kind,
                codecKey: codecKey,
                clockRate: clockRate,
                channels: channels,
                requestKeyframe: requestKeyframe,
                onError: (Object e) => stderr.writeln(
                    '[webdartc] receive pipeline error (ssrc=$ssrc): $e'),
              );

  /// W3C RTP Transport: Get an RtpPacketReceiver for direct packet access.
  Future<RtpPacketReceiver> replacePacketReceiver() async {
    _packetReceiver ??= RtpPacketReceiver(mid: null, ssrcs: [ssrc]);
    return _packetReceiver!;
  }

  /// Stream of received RTP packets for this track. Always emits raw packets
  /// in arrival order, independent of codec registration or the decode
  /// pipeline.
  Stream<RtpPacket> get onRtp => _controller.stream;

  void _deliver(RtpPacket packet, int arrivalUs) {
    _packetReceiver?.deliverPacket(packet);
    _controller.add(packet);
    _pipeline?.add(packet, arrivalUs);
  }

  /// Periodic pump (driven by PeerConnection's RTCP tick): releases jitter-
  /// buffered packets, depacketizes, decodes, and handles PLI retransmit.
  void _tick(int nowUs) => _pipeline?.tick(nowUs);

  void _close() {
    _pipeline?.close();
    unawaited(_controller.close());
  }
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

/// PeerConnection connection state. `newState` is the spec's `"new"` value (a
/// reserved word in Dart) — the state before any transport begins connecting.
enum PeerConnectionState {
  newState,
  closed,
  failed,
  disconnected,
  connecting,
  connected,
}

/// ICE gathering state (W3C `RTCIceGatheringState`). `newState` is the spec's
/// `"new"` value (a reserved word in Dart), mirroring how [IceConnectionState]
/// uses `iceNew`.
enum IceGatheringState {
  newState,
  gathering,
  complete,
}

/// DTLS transport state.
enum DtlsTransportState {
  closed,
  connecting,
  connected,
  failed,
}

/// W3C `RTCRtpTransceiverDirection`.
enum RtpTransceiverDirection {
  sendrecv,
  sendonly,
  recvonly,
  inactive,
  stopped;

  /// SDP direction token (`a=sendrecv` etc.). A stopped transceiver maps to
  /// `inactive` on the wire.
  String get sdpToken => switch (this) {
        RtpTransceiverDirection.sendrecv => 'sendrecv',
        RtpTransceiverDirection.sendonly => 'sendonly',
        RtpTransceiverDirection.recvonly => 'recvonly',
        RtpTransceiverDirection.inactive => 'inactive',
        RtpTransceiverDirection.stopped => 'inactive',
      };

  /// Parse an SDP direction token; unknown tokens fall back to `sendrecv`.
  static RtpTransceiverDirection fromToken(String token) => switch (token) {
        'sendonly' => RtpTransceiverDirection.sendonly,
        'recvonly' => RtpTransceiverDirection.recvonly,
        'inactive' => RtpTransceiverDirection.inactive,
        _ => RtpTransceiverDirection.sendrecv,
      };

  /// The negotiated direction (W3C `currentDirection`) from our preferred
  /// [local] direction and the [remote] direction on its SDP m-line — the
  /// intersection: we send only if we want to and the peer will receive,
  /// and vice-versa.
  static RtpTransceiverDirection negotiated(
      RtpTransceiverDirection local, RtpTransceiverDirection remote) {
    bool sends(RtpTransceiverDirection d) =>
        d == sendrecv || d == sendonly;
    bool receives(RtpTransceiverDirection d) =>
        d == sendrecv || d == recvonly;
    final send = sends(local) && receives(remote);
    final recv = receives(local) && sends(remote);
    if (send && recv) return sendrecv;
    if (send) return sendonly;
    if (recv) return recvonly;
    return inactive;
  }
}

/// W3C `RTCRtpEncodingParameters` — per-encoding send configuration. webdartc
/// has a single encoding per sender (no simulcast), so a sender's parameters
/// carry exactly one of these.
final class RtpEncodingParameters {
  /// Whether this encoding is actively sent. When false the sender drops
  /// outgoing RTP (W3C: an inactive encoding produces no media). This is the
  /// one field with a wire effect in webdartc's core.
  bool active;

  /// Maximum target bitrate in bits/sec, or null for unconstrained. Round-trips
  /// through get/setParameters so a codec backend (e.g. webdartc_flutter) can
  /// read it once wired up; webdartc's pure core stores it but does not act on
  /// it (it never paces the application's `sendRtp` calls).
  int? maxBitrate;

  /// Maximum frame rate in fps (video), or null. Stored-only advisory like
  /// [maxBitrate].
  double? maxFramerate;

  RtpEncodingParameters({
    this.active = true,
    this.maxBitrate,
    this.maxFramerate,
  });

  RtpEncodingParameters _copy() => RtpEncodingParameters(
        active: active,
        maxBitrate: maxBitrate,
        maxFramerate: maxFramerate,
      );
}

/// W3C `RTCRtpSendParameters` — returned by [RtpSender.getParameters] and
/// passed back to [RtpSender.setParameters].
final class RtpSendParameters {
  /// Opaque token from the last [RtpSender.getParameters]. [RtpSender
  /// .setParameters] rejects a value that doesn't match (W3C
  /// `InvalidStateError`), guarding against applying stale parameters.
  final String transactionId;

  /// Per-encoding parameters. The length is fixed at sender creation;
  /// [RtpSender.setParameters] must not add or remove entries.
  final List<RtpEncodingParameters> encodings;

  RtpSendParameters({required this.transactionId, required this.encodings});
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

  /// Send statistics for RTCP SR and `PeerConnection.getStats`.
  int _packetsSent = 0;
  int _octetsSent = 0;
  int _lastRtpTimestamp = 0;

  /// Total RTP packets put on the wire from this sender. Surfaced via
  /// `OutboundRtpStats.packetsSent`.
  int get packetsSent => _packetsSent;

  /// Total RTP payload bytes (sum of `payload.length` per `sendRtp`).
  /// Header bytes are excluded; matches the W3C
  /// `bytesSent`/`headerBytesSent` split (we only report payload here).
  int get bytesSent => _octetsSent;

  /// Single send encoding (no simulcast). Mutated by [setParameters]; read by
  /// [getParameters] and the [sendRtp] active-gate.
  final RtpEncodingParameters _encoding = RtpEncodingParameters();

  /// transactionId handed out by the last [getParameters], or null once it has
  /// been consumed by a [setParameters] — makes each token single-use.
  String? _paramsTransactionId;

  /// W3C: The MediaStreamTrack attached to this sender.
  MediaStreamTrack? _track;
  MediaStreamTrack? get track => _track;

  /// W3C `getParameters()` — a snapshot of the current send parameters with a
  /// fresh `transactionId` that the matching [setParameters] must echo back.
  RtpSendParameters getParameters() {
    final txId = Csprng.randomHex(8);
    _paramsTransactionId = txId;
    return RtpSendParameters(
      transactionId: txId,
      encodings: [_encoding._copy()],
    );
  }

  /// W3C `setParameters()` — apply mutable encoding fields (`active`,
  /// `maxBitrate`, `maxFramerate`). Throws if [params] didn't come from the
  /// most recent [getParameters] (stale `transactionId`) or changes the number
  /// of encodings — both `InvalidStateError`/`InvalidModificationError` in the
  /// spec. The token is single-use: a second call needs a fresh getParameters.
  Future<void> setParameters(RtpSendParameters params) async {
    if (_paramsTransactionId == null ||
        params.transactionId != _paramsTransactionId) {
      throw StateError(
          'setParameters: transactionId does not match the last getParameters');
    }
    if (params.encodings.length != 1) {
      throw StateError('setParameters: cannot change the number of encodings');
    }
    final e = params.encodings.single;
    _encoding.active = e.active;
    _encoding.maxBitrate = e.maxBitrate;
    _encoding.maxFramerate = e.maxFramerate;
    _paramsTransactionId = null;
  }

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
    // W3C: an inactive encoding produces no media — drop the packet before it
    // reaches the wire or touches the seq/timestamp/stat counters.
    if (!_encoding.active) return;
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

/// W3C `RTCRtpTransceiver` — a paired [RtpSender] / [RtpReceiver] for one
/// media m-line. Created by [PeerConnection.addTransceiver] /
/// [PeerConnection.addTrack] and listed by [PeerConnection.getTransceivers].
final class RtpTransceiver {
  /// Media kind: 'audio' or 'video'.
  final String kind;

  /// Codec names this transceiver prefers to offer, in order (internal).
  final List<String>? preferredCodecs;

  /// The sender for outgoing media, or null for a receive-only transceiver.
  RtpSender? sender;

  RtpReceiver? _receiver;
  String? _mid;
  RtpTransceiverDirection _direction;
  RtpTransceiverDirection? _currentDirection;

  RtpTransceiver._({
    required this.kind,
    RtpTransceiverDirection direction = RtpTransceiverDirection.sendrecv,
    this.preferredCodecs,
  }) : _direction = direction;

  /// The receiver for incoming media, or null until media arrives on this
  /// transceiver.
  RtpReceiver? get receiver => _receiver;

  /// The negotiated media-line identifier (BUNDLE `a=mid`), or null before
  /// the first negotiation.
  String? get mid => _mid;

  /// Preferred direction applied at the next negotiation (W3C `direction`).
  RtpTransceiverDirection get direction => _direction;

  /// Direction negotiated at the last offer/answer, or null before the first
  /// negotiation completes (W3C `currentDirection`).
  RtpTransceiverDirection? get currentDirection => _currentDirection;

  /// Whether [stop] has been called (W3C `stopped`).
  bool get stopped => _direction == RtpTransceiverDirection.stopped;

  /// W3C: set the preferred [direction] for the next negotiation.
  void setDirection(RtpTransceiverDirection direction) {
    if (stopped) throw StateError('RtpTransceiver has been stopped');
    _direction = direction;
  }

  /// W3C: stop the transceiver. It stops sending/receiving and negotiates as
  /// `inactive`; a subsequent [setDirection] throws.
  void stop() {
    if (stopped) return;
    _direction = RtpTransceiverDirection.stopped;
    _currentDirection = RtpTransceiverDirection.stopped;
    sender?._track = null;
    _receiver?._close();
  }
}
