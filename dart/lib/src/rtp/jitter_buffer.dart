/// RTP reorder / jitter buffer for a single SSRC.
///
/// Pure state machine: no I/O, no timers. The caller feeds arriving packets
/// via [add] (with a monotonic arrival timestamp in microseconds) and pulls
/// in-order, de-duplicated packets via [drain] (passing the current time on the
/// same clock). [drain] is meant to be called on a periodic tick.
///
/// Behaviour:
/// - Packets are released in ascending RTP sequence-number order, with 16-bit
///   wraparound handled (RFC 3550 §A.1).
/// - A small playout delay lets out-of-order packets settle before release.
/// - When a packet is missing, release waits up to [JitterBufferConfig
///   .gapTimeout] for it to arrive; after that the gap is skipped (the lost
///   packet is abandoned).
/// - Duplicates and packets that arrive after their slot was already released
///   ("too late") are dropped.
/// - If the buffer exceeds [JitterBufferConfig.maxPackets], the oldest gap is
///   skipped immediately to bound memory and latency.
library;

import 'dart:collection';

import 'packet.dart';

/// Tuning for [JitterBuffer]. Times are in microseconds.
final class JitterBufferConfig {
  /// How long the oldest buffered packet is held before playout begins / a
  /// contiguous run is released, giving reordered packets time to arrive.
  final int playoutDelay;

  /// How long to wait for a missing packet before skipping past it. Defaults
  /// to [playoutDelay].
  final int gapTimeout;

  /// Maximum number of buffered packets before the oldest gap is force-skipped.
  final int maxPackets;

  const JitterBufferConfig({
    this.playoutDelay = 50000, // 50 ms
    int? gapTimeout,
    this.maxPackets = 64,
  }) : gapTimeout = gapTimeout ?? playoutDelay;
}

class _Entry {
  final RtpPacket packet;
  final int arrivalUs;
  _Entry(this.packet, this.arrivalUs);
}

/// Per-SSRC RTP reorder buffer. See library docs for behaviour.
final class JitterBuffer {
  final JitterBufferConfig config;

  /// Buffered packets keyed by *extended* (unwrapped, monotonically growing)
  /// sequence number so ordering is natural across 16-bit wraparound.
  final _buffer = SplayTreeMap<int, _Entry>();

  /// Reference extended sequence number used to unwrap incoming 16-bit seqs —
  /// the highest extended value seen so far. Null until the first packet.
  int? _refExt;

  /// Next extended sequence number to release, or null before playout starts.
  int? _nextSeq;

  JitterBuffer({this.config = const JitterBufferConfig()});

  /// Number of packets currently buffered.
  int get length => _buffer.length;

  /// Extend a 16-bit [seq16] to a monotonic value relative to [_refExt],
  /// choosing the candidate closest to the reference to resolve wraparound.
  int _unwrap(int seq16) {
    final ref = _refExt;
    if (ref == null) return seq16;
    final refLow = ref & 0xFFFF;
    var delta = seq16 - refLow;
    if (delta > 32768) {
      delta -= 65536; // seq is behind ref across a wrap
    } else if (delta < -32768) {
      delta += 65536; // seq is ahead of ref across a wrap
    }
    return ref + delta;
  }

  /// Insert an arriving [packet] received at [arrivalUs] (microseconds, same
  /// monotonic clock passed to [drain]). Duplicates and too-late packets are
  /// dropped.
  void add(RtpPacket packet, int arrivalUs) {
    final ext = _unwrap(packet.sequenceNumber);
    // Drop packets for a slot we have already released.
    final next = _nextSeq;
    if (next != null && ext < next) return;
    // Insert unless a duplicate is already buffered (single map traversal).
    final added = _buffer.putIfAbsent(ext, () => _Entry(packet, arrivalUs));
    if (!identical(added.packet, packet)) return; // was a duplicate
    if (_refExt == null || ext > _refExt!) _refExt = ext;
  }

  /// Release the longest in-order run of packets that is ready at [nowUs].
  /// Returns an empty list when nothing is ready yet.
  List<RtpPacket> drain(int nowUs) {
    if (_buffer.isEmpty) return const [];

    // Start playout once the oldest buffered packet has aged past the playout
    // delay (or the buffer is already over its depth limit).
    if (_nextSeq == null) {
      final oldest = _buffer.firstKey()!;
      final aged = nowUs - _buffer[oldest]!.arrivalUs >= config.playoutDelay;
      if (!aged && _buffer.length <= config.maxPackets) return const [];
      _nextSeq = oldest;
    }

    List<RtpPacket>? out;
    while (_buffer.isNotEmpty) {
      final next = _nextSeq!;
      final entry = _buffer.remove(next);
      if (entry != null) {
        (out ??= <RtpPacket>[]).add(entry.packet);
        _nextSeq = next + 1;
        continue;
      }
      // Gap at `next`. Decide whether to keep waiting or skip it. Read the
      // oldest entry once instead of firstKey()+lookup.
      final oldestKey = _buffer.firstKey()!;
      final overdue =
          nowUs - _buffer[oldestKey]!.arrivalUs >= config.gapTimeout;
      final overflow = _buffer.length > config.maxPackets;
      if (overdue || overflow) {
        _nextSeq = oldestKey; // abandon the missing packet(s), jump to oldest
        continue;
      }
      break; // wait for the missing packet to arrive
    }
    return out ?? const [];
  }

  /// Flush all buffered packets in order, ignoring timing (e.g. on teardown).
  List<RtpPacket> flush() {
    final out = [for (final e in _buffer.values) e.packet];
    _buffer.clear();
    return out;
  }
}
