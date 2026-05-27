/// Pure-arithmetic helpers used when interpreting RTCP RR / SR report
/// blocks (RFC 3550 §6.4.1) into the W3C `RTCRemoteInboundRtpStreamStats`
/// shape. Kept separate from the parser so it can be fuzzed in isolation
/// without spinning up a full PeerConnection.
library;

/// Sign bit of the 24-bit two's-complement field used by RR's
/// cumulative-lost.
const int _signBit24 = 0x800000;

/// 24-bit value mask.
const int _mask24 = 0xFFFFFF;

/// 32-bit value mask, used to clamp the result of a wrapping subtract
/// into the compact-NTP range.
const int _mask32 = 0xFFFFFFFF;

/// Sign bit of the wrapped 32-bit delta produced by the compact-NTP
/// subtraction in [rttSeconds]; anything at or above this is treated
/// as a "negative" delta (wrap-around / clock skew).
const int _signBit32 = 0x80000000;

/// 1 second expressed in compact-NTP 1/65536-sec ticks. Used to
/// convert the integer compact-NTP delta to a fractional-second
/// `double` for the W3C `roundTripTime` field.
const double _compactNtpTicksPerSecond = 65536.0;

/// Mask used to keep only the low 16 bits of the seconds half of a
/// 64-bit NTP timestamp when collapsing to compact NTP.
const int _compactNtpHalfMask = 0xFFFF;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch
/// (1970-01-01). RFC 5905 §6.
const int ntpEpochOffsetSeconds = 2208988800;

/// 2^32 — the number of NTP fractional units in one second. Used to
/// convert sub-second precision (millisecond, micro-) into the
/// `ntp_frac` half of a 64-bit NTP timestamp.
const int ntpFracUnitsPerSecond = 4294967296;

/// 0–255 RR fraction-lost byte → 0.0–1.0 (W3C convention).
const double rtcpFractionLostScale = 256.0;

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
  return (v & _signBit24) != 0 ? v | ~_mask24 : v & _mask24;
}

/// Collapse a 64-bit NTP timestamp (split into 32-bit seconds and
/// 32-bit fraction halves) to its compact 32-bit form: low 16 bits of
/// seconds, high 16 bits of fraction. Compact NTP is what RR's
/// `lastSr` / `dlsr` fields carry, per RFC 3550 §6.4.1.
int compactNtpOf(int ntpSecs, int ntpFrac) =>
    ((ntpSecs & _compactNtpHalfMask) << 16) |
    ((ntpFrac >> 16) & _compactNtpHalfMask);

/// [now] expressed as a 64-bit NTP timestamp split into 32-bit
/// seconds (`high`) and 32-bit fractional (`low`) halves — the wire
/// format SR carries. Pure — callers pass `DateTime.now()` from the
/// I/O layer; tests can pin to a fixed instant. Each half is masked
/// to 32 bits so the seconds field wraps cleanly at the NTP epoch
/// rollover (RFC 5905 §6, the year-2036 wrap).
({int high, int low}) ntpTimestampOf(DateTime now) {
  final nowMs = now.millisecondsSinceEpoch;
  final high = ((nowMs ~/ 1000) + ntpEpochOffsetSeconds) & _mask32;
  final low = (((nowMs % 1000) * ntpFracUnitsPerSecond) ~/ 1000) & _mask32;
  return (high: high, low: low);
}

/// [now] expressed as compact NTP — convenience wrapper around
/// [ntpTimestampOf] that collapses the two halves via [compactNtpOf].
int currentCompactNtp(DateTime now) {
  final ts = ntpTimestampOf(now);
  return compactNtpOf(ts.high, ts.low);
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
  final delta = (nowCompactNtp - lastSr - dlsrNtp) & _mask32;
  // Treat the upper half of the 32-bit space as "negative" — either
  // clock skew or an outright wrap-around. Matches the spirit of
  // RFC 3550 §A.7 (which casts the delta to signed and treats
  // negatives as unmeasurable); we report `null` where libwebrtc
  // reports `0`. W3C allows either.
  if (delta >= _signBit32) return null;
  return delta / _compactNtpTicksPerSecond;
}
