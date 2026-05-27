/// Pure-arithmetic helpers used when interpreting RTCP RR / SR report
/// blocks (RFC 3550 §6.4.1) into the W3C `RTCRemoteInboundRtpStreamStats`
/// shape. Kept separate from the parser so it can be fuzzed in isolation
/// without spinning up a full PeerConnection.
library;

/// Sign-extend an unsigned 24-bit value into a Dart `int` (effectively
/// 64-bit on the VM). RTCP's "cumulative number of packets lost" field
/// is 24-bit two's-complement (RFC 3550 §6.4.1) and can legitimately go
/// negative when the receiver observes duplicates across our seq
/// rollover.
///
/// Pure / never throws. Pre-condition: `v` is in `[0, 0xFFFFFF]` —
/// callers parsing RTCP bytes always satisfy this, but the function is
/// total over any `int` for defensive use.
int sext24(int v) {
  // Bit 23 is the sign bit. When set, the top bits must all be 1.
  return (v & 0x800000) != 0 ? v | ~0xFFFFFF : v & 0xFFFFFF;
}

/// Compute the round-trip time between sending a Sender Report and
/// receiving the matching Receiver Report block, per RFC 3550 §6.4.1.
///
/// All three arguments are 32-bit compact-NTP timestamps (middle 32
/// bits of the full 64-bit NTP):
///   * [nowCompactNtp] — current time on this side
///   * [lastSr] — value the remote echoed from one of our recent SRs
///   * [dlsrNtp] — time the remote spent between receiving that SR
///     and emitting this RR (1/65536 sec ticks)
///
/// Returns the RTT in **seconds** (double). Returns `null` when:
///   * `lastSr == 0` (the remote has never received an SR from us yet),
///   * the computed delta is "negative" — interpreted as wrap-around
///     or clock skew (delta's high bit set after the 32-bit mask).
///
/// Pure / never throws.
double? rttSeconds({
  required int nowCompactNtp,
  required int lastSr,
  required int dlsrNtp,
}) {
  if (lastSr == 0) return null;
  final delta = (nowCompactNtp - lastSr - dlsrNtp) & 0xFFFFFFFF;
  // Treat the upper half of the 32-bit space as "negative" — either
  // clock skew or an outright wrap-around. RFC 3550 doesn't say what
  // to do, so we conservatively decline to report.
  if (delta >= 0x80000000) return null;
  return delta / 65536.0;
}
