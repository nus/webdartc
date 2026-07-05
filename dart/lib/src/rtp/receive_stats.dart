/// Receive-side RTP reception accounting for a single SSRC (RFC 3550
/// §A.1/§A.3 sequence + loss, §A.8 interarrival jitter).
///
/// Pure state machine — feed it each packet's sequence number, RTP
/// timestamp, and local arrival time, then read the derived counters. No
/// I/O, so it can be unit-tested / fuzzed in isolation from the transport.
library;

/// Tracks loss and interarrival jitter for one received RTP stream.
final class RtpReceptionTracker {
  /// RTP clock rate (Hz) of the stream — used to convert local arrival
  /// time into RTP timestamp units for the jitter estimate.
  final int clockRate;

  RtpReceptionTracker(this.clockRate);

  static const int _seqMod = 1 << 16;
  // A forward jump larger than this is treated as reordering / duplication
  // rather than in-order delivery (RFC 3550 §A.1 MAX_DROPOUT).
  static const int _maxDropout = 3000;

  bool _started = false;
  int _baseSeq = 0;
  int _maxSeq = 0; // low 16 bits of the highest in-order seq seen
  int _cycles = 0; // multiples of _seqMod (wrap count << 16)
  int _received = 0;
  int _expectedPrior = 0;
  int _receivedPrior = 0;

  double _jitter = 0; // RTP timestamp units
  int? _lastTransit;

  /// Total packets received (including duplicates / reordered).
  int get packetsReceived => _received;

  /// Extended highest sequence number (cycles + max), for RTCP RR.
  int get extendedHighestSeq => _started ? _cycles + _maxSeq : 0;

  /// Packets expected = extended highest − base + 1 (RFC 3550 §A.3).
  int get expected => _started ? extendedHighestSeq - _baseSeq + 1 : 0;

  /// Cumulative packets lost (expected − received). May be negative when
  /// duplicates were received (RFC 3550 §6.4.1).
  int get cumulativeLost => expected - _received;

  /// Interarrival jitter in RTP timestamp units (RTCP RR field).
  double get jitter => _jitter;

  /// Interarrival jitter in seconds (W3C `jitter` convention).
  double get jitterSeconds => clockRate > 0 ? _jitter / clockRate : 0;

  /// Record one received packet.
  void onPacket({
    required int seq,
    required int rtpTimestamp,
    required int arrivalUs,
  }) {
    if (!_started) {
      _started = true;
      _baseSeq = seq;
      _maxSeq = seq;
      _received = 1;
      _updateJitter(rtpTimestamp, arrivalUs);
      return;
    }
    _received++;
    final udelta = (seq - _maxSeq) & (_seqMod - 1);
    if (udelta < _maxDropout) {
      // In order, possibly with a gap (loss).
      if (seq < _maxSeq) _cycles += _seqMod; // sequence wrapped
      _maxSeq = seq;
    }
    // else: duplicate or reordered — counted in `received`, max unchanged.
    _updateJitter(rtpTimestamp, arrivalUs);
  }

  /// Fraction of packets lost over the interval since the previous call,
  /// as the RTCP RR 8-bit fixed-point value (0–255). Advances the interval
  /// counters (RFC 3550 §A.3), so call it once per RR emitted.
  int takeFractionLost() {
    final expectedInterval = expected - _expectedPrior;
    final receivedInterval = _received - _receivedPrior;
    _expectedPrior = expected;
    _receivedPrior = _received;
    final lost = expectedInterval - receivedInterval;
    if (expectedInterval == 0 || lost <= 0) return 0;
    return ((lost << 8) ~/ expectedInterval).clamp(0, 255);
  }

  void _updateJitter(int rtpTimestamp, int arrivalUs) {
    if (clockRate <= 0) return;
    // Arrival time expressed in the stream's RTP timestamp units.
    final arrivalRtp = (arrivalUs * clockRate) ~/ 1000000;
    final transit = arrivalRtp - rtpTimestamp;
    final last = _lastTransit;
    if (last != null) {
      var d = transit - last;
      if (d < 0) d = -d;
      _jitter += (d - _jitter) / 16.0;
    }
    _lastTransit = transit;
  }
}
