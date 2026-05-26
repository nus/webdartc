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

  const TransportStats({
    required super.id,
    required super.timestamp,
    required this.bytesSent,
    required this.bytesReceived,
    required this.packetsSent,
    required this.packetsReceived,
    this.selectedCandidatePairId,
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

  const CandidatePairStats({
    required super.id,
    required super.timestamp,
    required this.localCandidateId,
    required this.remoteCandidateId,
    required this.state,
    required this.nominated,
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
