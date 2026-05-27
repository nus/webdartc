import 'package:test/test.dart';
import 'package:webdartc/rtp/rtcp_math.dart';

void main() {
  group('sext24', () {
    test('positive values pass through unchanged', () {
      expect(sext24(0), 0);
      expect(sext24(1), 1);
      expect(sext24(0x7FFFFF), 0x7FFFFF); // max 24-bit positive
    });

    test('sign bit set extends to negative', () {
      expect(sext24(0x800000), -0x800000); // min 24-bit negative
      expect(sext24(0xFFFFFF), -1); // all-ones is -1
      expect(sext24(0x800001), -0x7FFFFF);
    });

    test('inputs above 24 bits are masked', () {
      // High bits beyond bit 23 are discarded — anything outside the
      // 24-bit range is undefined per RFC but the function chooses to
      // treat it as the 24-bit slice of the input.
      expect(sext24(0x1000000) & 0xFFFFFF, 0);
      expect(sext24(0xFF000000) & 0xFFFFFF, 0);
    });
  });

  group('compactNtpOf', () {
    test('all zeros → zero', () {
      expect(compactNtpOf(0, 0), 0);
    });

    test('low 16 bits of secs become high 16 bits of compact', () {
      // ntpSecs = 0x0000ABCD, ntpFrac = 0 → compact = 0xABCD0000
      expect(compactNtpOf(0xABCD, 0), 0xABCD0000);
    });

    test('high 16 bits of frac become low 16 bits of compact', () {
      // ntpSecs = 0, ntpFrac = 0xDEAD0000 → compact = 0x0000DEAD
      expect(compactNtpOf(0, 0xDEAD0000), 0x0000DEAD);
    });

    test('only the middle 32 bits of the full 64-bit NTP survive', () {
      // High 16 of secs + low 16 of frac are dropped.
      // ntpSecs = 0xFFFF0001 (high half: dropped, low half: 0x0001)
      // ntpFrac = 0x0002FFFF (high half: 0x0002, low half: dropped)
      // → compact = (0x0001 << 16) | 0x0002 = 0x00010002
      expect(compactNtpOf(0xFFFF0001, 0x0002FFFF), 0x00010002);
    });
  });

  group('ntpTimestampOf', () {
    test('NTP epoch — exactly 2208988800 seconds past Unix epoch', () {
      final unixEpoch = DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);
      final ts = ntpTimestampOf(unixEpoch);
      // High = ntpEpochOffsetSeconds; low fractional = 0.
      expect(ts.high, ntpEpochOffsetSeconds);
      expect(ts.low, 0);
    });

    test('one second past the Unix epoch → secs incremented, frac zero', () {
      final t = DateTime.fromMillisecondsSinceEpoch(1000, isUtc: true);
      final ts = ntpTimestampOf(t);
      expect(ts.high, ntpEpochOffsetSeconds + 1);
      expect(ts.low, 0);
    });

    test('half a second → frac is roughly 2^31', () {
      final t = DateTime.fromMillisecondsSinceEpoch(500, isUtc: true);
      final ts = ntpTimestampOf(t);
      expect(ts.high, ntpEpochOffsetSeconds);
      // 0.5 sec × 2^32 = 2^31. Integer-divided form drops the last
      // bit; 500 × 4294967296 ~/ 1000 = 2147483648 exactly here.
      expect(ts.low, 0x80000000);
    });

    test('both halves stay in 32-bit range', () {
      final t = DateTime.now();
      final ts = ntpTimestampOf(t);
      expect(ts.high, greaterThanOrEqualTo(0));
      expect(ts.high, lessThanOrEqualTo(0xFFFFFFFF));
      expect(ts.low, greaterThanOrEqualTo(0));
      expect(ts.low, lessThanOrEqualTo(0xFFFFFFFF));
    });
  });

  group('currentCompactNtp', () {
    test('matches compactNtpOf(ntpTimestampOf(now))', () {
      // The convenience wrapper must produce the same compact form
      // the SR-receive path would derive from the wire bytes via
      // ntpTimestampOf + compactNtpOf.
      final t = DateTime.fromMillisecondsSinceEpoch(1700000000000, isUtc: true);
      final ts = ntpTimestampOf(t);
      expect(currentCompactNtp(t), compactNtpOf(ts.high, ts.low));
    });
  });

  group('rttSeconds', () {
    test('null when lastSr is 0', () {
      expect(
          rttSeconds(nowCompactNtp: 0x12345678, lastSr: 0, dlsrNtp: 0),
          isNull);
    });

    test('measures a 250 ms RTT precisely (loopback-ish)', () {
      // 250 ms = 250/1000 × 65536 ≈ 16384 compact-NTP ticks.
      // sender SR sent at lastSr; receiver replied 50ms later
      // (dlsr=3276 ticks). Now is `lastSr + 250ms RTT + 50ms dlsr`
      // in ticks. Helper recovers 250 ms.
      const lastSr = 0x10000000;
      const dlsrNtp = (50 * 65536) ~/ 1000;
      const rttNtp = (250 * 65536) ~/ 1000;
      final now = (lastSr + rttNtp + dlsrNtp) & 0xFFFFFFFF;
      final rtt = rttSeconds(
        nowCompactNtp: now,
        lastSr: lastSr,
        dlsrNtp: dlsrNtp,
      );
      expect(rtt, isNotNull);
      // 250 ms within 1/65536 sec slop.
      expect((rtt! - 0.250).abs(), lessThan(1 / 65536));
    });

    test('returns null when the delta is "negative" (lastSr > now)', () {
      // lastSr in the future relative to now → 32-bit unsigned delta
      // lands in the upper half → null.
      expect(
          rttSeconds(
              nowCompactNtp: 100, lastSr: 200, dlsrNtp: 0),
          isNull);
    });

    test('handles compact-NTP wrap (now smaller than lastSr by < 2^31)', () {
      // Wrap-around case: nowCompact has rolled past 2^32 while
      // lastSr remembers the pre-wrap value. As long as the masked
      // delta is in the lower half, RTT is valid.
      const lastSr = 0xFFFFFF00;
      const dlsrNtp = 0;
      // now = lastSr + 0x100 (small positive delta) — wraps to
      // 0x0000005F via 32-bit mask.
      final now = (lastSr + 0x100) & 0xFFFFFFFF;
      final rtt = rttSeconds(
          nowCompactNtp: now, lastSr: lastSr, dlsrNtp: dlsrNtp);
      expect(rtt, isNotNull);
      // 0x100 ticks / 65536 = 0.00390625 sec
      expect(rtt!, closeTo(0x100 / 65536.0, 1e-9));
    });
  });
}
