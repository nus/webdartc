/// W3C WebRTC `RTCStatsReport` (§8) data types.
///
/// `PeerConnection.getStats()` returns a snapshot of every active stat
/// the implementation tracks. Each [RtcStats] has:
///   * a stable [id] (same value across snapshots for the same object,
///     e.g. a single ICE candidate pair),
///   * a [type] discriminator picked from [RtcStatsType],
///   * a [timestamp] (microseconds since epoch, monotonic-ish — derived
///     from `DateTime.now`).
///
/// Counters in this report are *monotonic* across calls (W3C §8.1).
/// Callers compute deltas between two snapshots themselves.
library;

import '../ice/candidate.dart';

enum RtcStatsType {
  /// Inbound RTP stream stats keyed by SSRC.
  inboundRtp,

  /// Outbound RTP stream stats keyed by SSRC.
  outboundRtp,

  /// RTCP-RR-derived stats: what the remote peer reports back about
  /// receiving *our* outbound stream.
  remoteInboundRtp,

  /// RTCP-SR-derived stats: what the remote peer reports about *its* own
  /// outbound stream (i.e. our inbound stream).
  remoteOutboundRtp,

  /// One [CandidatePair] from the ICE agent.
  candidatePair,

  /// A local ICE candidate.
  localCandidate,

  /// A remote ICE candidate.
  remoteCandidate,

  /// Transport (ICE + DTLS) aggregate.
  transport,

  /// A `DataChannel` instance.
  dataChannel,

  /// PeerConnection-wide aggregate.
  peerConnection,

  /// One negotiated codec per (m-line, payloadType).
  codec,

  /// Application-side source feeding an outbound RTP stream.
  mediaSource,

  /// DTLS certificate (local or remote).
  certificate,
}

/// Base class for an entry in a [RtcStatsReport].
sealed class RtcStats {
  final String id;
  final RtcStatsType type;
  final DateTime timestamp;

  const RtcStats({
    required this.id,
    required this.type,
    required this.timestamp,
  });
}

/// Snapshot returned by `PeerConnection.getStats()`.
final class RtcStatsReport {
  final Map<String, RtcStats> _entries;

  const RtcStatsReport(this._entries);

  /// Stats keyed by stable [RtcStats.id].
  Map<String, RtcStats> get entries => _entries;

  Iterable<RtcStats> get values => _entries.values;

  RtcStats? operator [](String id) => _entries[id];

  /// All entries of a given [type].
  Iterable<T> ofType<T extends RtcStats>(RtcStatsType type) =>
      _entries.values.where((s) => s.type == type).cast<T>();
}

/// PeerConnection-wide aggregate. `id` is always `pc`.
final class PeerConnectionStats extends RtcStats {
  final int dataChannelsOpened;
  final int dataChannelsClosed;

  const PeerConnectionStats({
    required super.id,
    required super.timestamp,
    required this.dataChannelsOpened,
    required this.dataChannelsClosed,
  }) : super(type: RtcStatsType.peerConnection);
}

/// Aggregate counters for the underlying transport (ICE + DTLS).
/// Bytes here are the post-DTLS plaintext byte count for app payloads
/// plus the raw byte count for STUN/ICE/TURN control traffic. The W3C
/// "bytesSent/Received" definition is intentionally loose; this gives
/// callers a usable approximation of wire activity.
final class TransportStats extends RtcStats {
  final int bytesSent;
  final int bytesReceived;
  final int packetsSent;
  final int packetsReceived;

  /// `id` of the currently-selected [CandidatePairStats], or `null` if
  /// ICE hasn't nominated a pair.
  final String? selectedCandidatePairId;

  /// `id` of the [CertificateStats] entries for the DTLS certificates
  /// in use, or `null` if the handshake hasn't completed.
  final String? localCertificateId;
  final String? remoteCertificateId;

  const TransportStats({
    required super.id,
    required super.timestamp,
    required this.bytesSent,
    required this.bytesReceived,
    required this.packetsSent,
    required this.packetsReceived,
    this.selectedCandidatePairId,
    this.localCertificateId,
    this.remoteCertificateId,
  }) : super(type: RtcStatsType.transport);
}

/// One ICE candidate pair. State + nomination mirror RFC 8445; bytes
/// are subset of the transport totals attributable to this specific
/// pair (currently only populated for the *selected* pair — others
/// stay at zero).
final class CandidatePairStats extends RtcStats {
  final String localCandidateId;
  final String remoteCandidateId;
  final String state; // "frozen" / "waiting" / "in-progress" / "succeeded" / "failed"
  final bool nominated;

  /// Most recent connectivity-check round-trip time in seconds, or
  /// `null` if the pair hasn't completed a check yet. Measured from
  /// the STUN Binding Request transmit to the matching response
  /// receive (RFC 8445 §6.1.4).
  final double? currentRoundTripTime;

  const CandidatePairStats({
    required super.id,
    required super.timestamp,
    required this.localCandidateId,
    required this.remoteCandidateId,
    required this.state,
    required this.nominated,
    this.currentRoundTripTime,
  }) : super(type: RtcStatsType.candidatePair);
}

/// One local or remote ICE candidate.
final class CandidateStats extends RtcStats {
  final String ip;
  final int port;
  final String protocol; // "udp"
  final IceCandidateType candidateType;
  final int priority;

  const CandidateStats({
    required super.id,
    required super.type,
    required super.timestamp,
    required this.ip,
    required this.port,
    required this.protocol,
    required this.candidateType,
    required this.priority,
  });
}

/// Per-SSRC stats for an RTP stream this connection is sending.
/// W3C `RTCOutboundRtpStreamStats`.
final class OutboundRtpStats extends RtcStats {
  final int ssrc;
  final String kind; // "audio" | "video"
  final int packetsSent;

  /// Total RTP payload bytes sent for this SSRC (does not include the
  /// RTP header). Matches the `_octetsSent` count `RtpSender` keeps
  /// for RTCP SR.
  final int bytesSent;

  /// `id` of the [CodecStats] for the payload type this stream is
  /// emitting, or `null` if the codec hasn't been negotiated yet.
  final String? codecId;

  /// `id` of the [MediaSourceStats] feeding this stream — usually the
  /// `media-source-<trackId>` for the sender's attached track. Null
  /// when no track is attached.
  final String? mediaSourceId;

  const OutboundRtpStats({
    required super.id,
    required super.timestamp,
    required this.ssrc,
    required this.kind,
    required this.packetsSent,
    required this.bytesSent,
    this.codecId,
    this.mediaSourceId,
  }) : super(type: RtcStatsType.outboundRtp);
}

/// What the remote peer reports back (via RTCP Receiver Report) about
/// receiving our outbound stream. W3C `RTCRemoteInboundRtpStreamStats`.
/// Keyed by *our* outbound SSRC — the same SSRC the remote echoes in
/// the RR's report block.
final class RemoteInboundRtpStats extends RtcStats {
  final int ssrc;

  /// Id of the corresponding local [OutboundRtpStats] entry
  /// (`outbound-rtp-<ssrc>`). Callers cross-reference the two to see
  /// "we sent N, the remote received N − packetsLost" pairs.
  final String localId;

  /// Cumulative packets lost as reported by the remote. May be
  /// negative when the remote received duplicates after our seq
  /// rollover (RFC 3550 §6.4.1, 24-bit signed).
  final int packetsLost;

  /// Fraction of packets lost since the last report, 0.0–1.0.
  final double fractionLost;

  /// Inter-arrival jitter in seconds (RR jitter divided by RTP clock
  /// rate; W3C convention).
  final double jitter;

  /// Round-trip time in seconds derived from `lastSr` + `dlsr` in the
  /// RR (RFC 3550 §6.4.1). Null until at least one RR has been
  /// received that references one of our SRs.
  final double? roundTripTime;

  const RemoteInboundRtpStats({
    required super.id,
    required super.timestamp,
    required this.ssrc,
    required this.localId,
    required this.packetsLost,
    required this.fractionLost,
    required this.jitter,
    required this.roundTripTime,
  }) : super(type: RtcStatsType.remoteInboundRtp);
}

/// Per-SSRC stats for an RTP stream this connection is receiving.
/// W3C `RTCInboundRtpStreamStats`.
final class InboundRtpStats extends RtcStats {
  final int ssrc;
  final String kind; // "audio" | "video"
  final int packetsReceived;

  /// Total RTP payload bytes received for this SSRC (no RTP header).
  final int bytesReceived;

  /// Cumulative packets lost on this stream (RFC 3550 §A.3 — expected
  /// minus received). May be negative when duplicates were received.
  final int packetsLost;

  /// Interarrival jitter in seconds (RFC 3550 §A.8, divided by the RTP
  /// clock rate — W3C convention).
  final double jitter;

  /// `id` of the [CodecStats] for the payload type this stream carries,
  /// or `null` if the PT isn't mapped to a negotiated codec.
  final String? codecId;

  const InboundRtpStats({
    required super.id,
    required super.timestamp,
    required this.ssrc,
    required this.kind,
    required this.packetsReceived,
    required this.bytesReceived,
    required this.packetsLost,
    required this.jitter,
    this.codecId,
  }) : super(type: RtcStatsType.inboundRtp);
}

/// What the remote peer reports about *its* outbound stream via RTCP
/// Sender Report — i.e. the sending counterpart of one of our inbound
/// streams. W3C `RTCRemoteOutboundRtpStreamStats`. Keyed by the remote
/// SSRC (the same SSRC we receive on).
final class RemoteOutboundRtpStats extends RtcStats {
  final int ssrc;
  final String kind; // "audio" | "video"

  /// `id` of the corresponding local [InboundRtpStats] entry
  /// (`inbound-rtp-<ssrc>`).
  final String localId;

  /// Packets the remote reports having sent for this SSRC (SR sender's
  /// packet count).
  final int packetsSent;

  /// RTP payload bytes the remote reports having sent (SR octet count).
  final int bytesSent;

  /// The remote's wall-clock time when it emitted the SR (its NTP
  /// timestamp), or `null` if no SR has been received yet.
  final DateTime? remoteTimestamp;

  /// Number of Sender Reports received for this SSRC.
  final int reportsReceived;

  const RemoteOutboundRtpStats({
    required super.id,
    required super.timestamp,
    required this.ssrc,
    required this.kind,
    required this.localId,
    required this.packetsSent,
    required this.bytesSent,
    required this.remoteTimestamp,
    required this.reportsReceived,
  }) : super(type: RtcStatsType.remoteOutboundRtp);
}

/// One negotiated codec for an m-line (RFC 8866 `a=rtpmap`).
/// W3C `RTCCodecStats`. The `id` shape is `codec-<mid>-<payloadType>`
/// so callers can find codecs for a specific track via the m-line ID
/// the SDP carries.
final class CodecStats extends RtcStats {
  final int payloadType;
  final String mimeType; // e.g. "audio/opus", "video/VP8"
  final int clockRate;
  final int? channels;
  final String? sdpFmtpLine; // raw `a=fmtp` params, no PT prefix

  const CodecStats({
    required super.id,
    required super.timestamp,
    required this.payloadType,
    required this.mimeType,
    required this.clockRate,
    this.channels,
    this.sdpFmtpLine,
  }) : super(type: RtcStatsType.codec);
}

/// Application-side source feeding an outbound RTP stream — the
/// MediaStreamTrack the sender is attached to. W3C `RTCMediaSourceStats`.
/// MVP exposes just identity + kind; video frame dimensions / audio
/// level are deferred (require per-frame instrumentation).
final class MediaSourceStats extends RtcStats {
  final String trackIdentifier;
  final String kind; // "audio" | "video"

  const MediaSourceStats({
    required super.id,
    required super.timestamp,
    required this.trackIdentifier,
    required this.kind,
  }) : super(type: RtcStatsType.mediaSource);
}

/// DTLS certificate fingerprint (W3C `RTCCertificateStats`). One
/// entry per role (local + remote). The `base64Certificate` field
/// W3C also defines isn't exposed yet — the DTLS module only retains
/// the verified fingerprint.
final class CertificateStats extends RtcStats {
  final String fingerprint; // hex, colon-separated (`AA:BB:CC:...`)
  final String fingerprintAlgorithm; // e.g. "sha-256"

  const CertificateStats({
    required super.id,
    required super.timestamp,
    required this.fingerprint,
    required this.fingerprintAlgorithm,
  }) : super(type: RtcStatsType.certificate);
}

/// One open / opening DataChannel.
final class DataChannelStats extends RtcStats {
  final String label;
  final String state; // "connecting" / "open" / "closing" / "closed"
  final int messagesSent;
  final int bytesSent;
  final int messagesReceived;
  final int bytesReceived;

  const DataChannelStats({
    required super.id,
    required super.timestamp,
    required this.label,
    required this.state,
    required this.messagesSent,
    required this.bytesSent,
    required this.messagesReceived,
    required this.bytesReceived,
  }) : super(type: RtcStatsType.dataChannel);
}
