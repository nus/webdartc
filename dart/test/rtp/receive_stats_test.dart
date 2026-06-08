import 'package:test/test.dart';
import 'package:webdartc/rtp/receive_stats.dart';

void main() {
  group('RtpReceptionTracker — loss (RFC 3550 §A.3)', () {
    test('in-order delivery reports no loss', () {
      final t = RtpReceptionTracker(90000);
      for (var seq = 100; seq < 105; seq++) {
        t.onPacket(seq: seq, rtpTimestamp: seq * 3000, arrivalUs: seq * 33000);
      }
      expect(t.packetsReceived, 5);
      expect(t.extendedHighestSeq, 104);
      expect(t.expected, 5);
      expect(t.cumulativeLost, 0);
    });

    test('a gap is counted as one lost packet', () {
      final t = RtpReceptionTracker(90000);
      for (final seq in [100, 101, 103, 104]) {
        t.onPacket(seq: seq, rtpTimestamp: seq * 3000, arrivalUs: seq * 33000);
      }
      expect(t.packetsReceived, 4);
      expect(t.expected, 5); // base 100 .. max 104
      expect(t.cumulativeLost, 1); // 102 missing
    });

    test('a duplicate yields negative cumulative loss', () {
      final t = RtpReceptionTracker(90000);
      for (final seq in [100, 101, 101]) {
        t.onPacket(seq: seq, rtpTimestamp: seq * 3000, arrivalUs: seq * 33000);
      }
      expect(t.packetsReceived, 3);
      expect(t.expected, 2); // max stays 101
      expect(t.cumulativeLost, -1);
    });

    test('sequence wrap advances the cycle count', () {
      final t = RtpReceptionTracker(90000);
      for (final seq in [65534, 65535, 0, 1]) {
        t.onPacket(seq: seq, rtpTimestamp: 0, arrivalUs: 0);
      }
      expect(t.packetsReceived, 4);
      expect(t.extendedHighestSeq, 65537); // 1 cycle + seq 1
      expect(t.expected, 4); // base 65534 .. extended max 65537
      expect(t.cumulativeLost, 0);
    });

    test('takeFractionLost reports per-interval loss as 8-bit fixed point', () {
      final t = RtpReceptionTracker(90000);
      // 4 of every 4 expected arrive → fraction 0.
      for (final seq in [10, 11, 12, 13]) {
        t.onPacket(seq: seq, rtpTimestamp: 0, arrivalUs: 0);
      }
      expect(t.takeFractionLost(), 0);
      // Next interval: expect 14..17 (4), but 15 and 16 are lost → 2/4 lost.
      for (final seq in [14, 17]) {
        t.onPacket(seq: seq, rtpTimestamp: 0, arrivalUs: 0);
      }
      // 2 lost of 4 expected = 128/256.
      expect(t.takeFractionLost(), 128);
    });
  });

  group('RtpReceptionTracker — jitter (RFC 3550 §A.8)', () {
    test('evenly spaced arrivals keep jitter at zero', () {
      final t = RtpReceptionTracker(8000);
      // 20 ms spacing at 8 kHz = 160 RTP units; arrival spacing matches.
      for (var i = 0; i < 5; i++) {
        t.onPacket(seq: 100 + i, rtpTimestamp: i * 160, arrivalUs: i * 20000);
      }
      expect(t.jitter, closeTo(0, 1e-9));
      expect(t.jitterSeconds, closeTo(0, 1e-9));
    });

    test('a late arrival raises the jitter estimate', () {
      final t = RtpReceptionTracker(8000);
      for (var i = 0; i < 3; i++) {
        t.onPacket(seq: 100 + i, rtpTimestamp: i * 160, arrivalUs: i * 20000);
      }
      expect(t.jitter, closeTo(0, 1e-9));
      // 4th packet arrives 20 ms late (80 ms instead of 60 ms).
      t.onPacket(seq: 103, rtpTimestamp: 3 * 160, arrivalUs: 80000);
      // D = 160 RTP units; jitter += (160 - 0)/16 = 10.
      expect(t.jitter, closeTo(10, 1e-9));
      expect(t.jitterSeconds, closeTo(10 / 8000, 1e-12));
    });
  });
}
