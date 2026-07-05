import 'dart:math';

import 'candidate.dart';

enum CandidatePairState { waiting, inProgress, succeeded, failed, frozen }

/// A candidate pair (RFC 8445 §6).
final class CandidatePair {
  final IceCandidate local;
  final IceCandidate remote;
  CandidatePairState state;
  bool nominated;
  int? roundTripTimeMs;

  CandidatePair({
    required this.local,
    required this.remote,
    this.state = CandidatePairState.frozen,
    this.nominated = false,
  });

  /// Pair priority (RFC 8445 §6.1.2.3).
  int get priority {
    final g = local.priority;
    final d = remote.priority;
    return ((1 << 32) * min(g, d) + 2 * max(g, d) + (g > d ? 1 : 0)).toInt();
  }

  String get foundation => '${local.foundation}:${remote.foundation}';

  @override
  String toString() =>
      'CandidatePair(${local.ip}:${local.port} <-> ${remote.ip}:${remote.port} $state)';
}
