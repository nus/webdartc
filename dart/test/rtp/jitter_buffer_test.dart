import 'dart:typed_data';

import 'package:webdartc/rtp/jitter_buffer.dart';
import 'package:webdartc/rtp/parser.dart';
import 'package:test/test.dart';

RtpPacket _pkt(int seq, {int ts = 0}) => RtpPacket(
      payloadType: 96,
      sequenceNumber: seq & 0xFFFF,
      timestamp: ts,
      ssrc: 0x1234,
      payload: Uint8List.fromList([seq & 0xFF]),
    );

List<int> _seqs(List<RtpPacket> pkts) => [for (final p in pkts) p.sequenceNumber];

void main() {
  // No playout delay so packets release as soon as they are contiguous; keeps
  // ordering/dedup assertions independent of timing.
  const noDelay = JitterBufferConfig(playoutDelay: 0, gapTimeout: 0);

  test('releases in-order packets in sequence', () {
    final jb = JitterBuffer(config: noDelay);
    for (var s = 1; s <= 5; s++) {
      jb.add(_pkt(s), s * 1000);
    }
    expect(_seqs(jb.drain(10000)), [1, 2, 3, 4, 5]);
    expect(jb.length, 0);
  });

  test('reorders out-of-order arrivals', () {
    final jb = JitterBuffer(config: noDelay);
    jb.add(_pkt(1), 1000);
    jb.add(_pkt(3), 1000);
    jb.add(_pkt(2), 1000); // arrives late, before playout
    expect(_seqs(jb.drain(10000)), [1, 2, 3]);
  });

  test('holds a contiguous prefix and waits for a gap', () {
    // Non-zero gap timeout so the missing packet is awaited, not skipped.
    final jb = JitterBuffer(
        config: const JitterBufferConfig(playoutDelay: 0, gapTimeout: 5000));
    jb.add(_pkt(1), 1000);
    jb.add(_pkt(2), 1000);
    jb.add(_pkt(4), 1000); // 3 is missing
    // 1,2 release; 4 is held waiting for 3 (gap not yet overdue at t=1000).
    expect(_seqs(jb.drain(1000)), [1, 2]);
    expect(jb.length, 1);
    // 3 arrives — now 3,4 release.
    jb.add(_pkt(3), 1500);
    expect(_seqs(jb.drain(1500)), [3, 4]);
  });

  test('skips a missing packet after gap timeout', () {
    final jb = JitterBuffer(
        config: const JitterBufferConfig(playoutDelay: 0, gapTimeout: 5000));
    jb.add(_pkt(1), 1000);
    jb.add(_pkt(3), 2000); // 2 missing
    expect(_seqs(jb.drain(2000)), [1]); // wait for 2
    expect(jb.length, 1);
    // After gap timeout elapses relative to oldest buffered (seq 3 @ 2000),
    // seq 2 is abandoned and 3 releases.
    expect(_seqs(jb.drain(2000 + 5000)), [3]);
  });

  test('drops duplicates', () {
    final jb = JitterBuffer(config: noDelay);
    jb.add(_pkt(1), 1000);
    jb.add(_pkt(1), 1000); // duplicate before release
    expect(_seqs(jb.drain(10000)), [1]);
    expect(jb.length, 0);
  });

  test('drops too-late packets for an already-released slot', () {
    final jb = JitterBuffer(config: noDelay);
    jb.add(_pkt(2), 1000);
    jb.add(_pkt(3), 1000);
    expect(_seqs(jb.drain(10000)), [2, 3]);
    // seq 1 arrives after 2 already played — must be dropped.
    jb.add(_pkt(1), 2000);
    expect(jb.length, 0);
    expect(_seqs(jb.drain(10000)), isEmpty);
  });

  test('handles 16-bit sequence wraparound', () {
    final jb = JitterBuffer(config: noDelay);
    jb.add(_pkt(65534), 1000);
    jb.add(_pkt(65535), 1000);
    jb.add(_pkt(0), 1000); // wraps to 0
    jb.add(_pkt(1), 1000);
    expect(_seqs(jb.drain(10000)), [65534, 65535, 0, 1]);
  });

  test('reorders across the wraparound boundary', () {
    final jb = JitterBuffer(config: noDelay);
    jb.add(_pkt(65535), 1000);
    jb.add(_pkt(1), 1000);
    jb.add(_pkt(0), 1000); // out of order, across the wrap
    expect(_seqs(jb.drain(10000)), [65535, 0, 1]);
  });

  test('respects playout delay before first release', () {
    final jb = JitterBuffer(
        config: const JitterBufferConfig(playoutDelay: 50000, gapTimeout: 50000));
    jb.add(_pkt(1), 1000);
    expect(jb.drain(1000), isEmpty); // not aged yet
    expect(jb.drain(1000 + 49999), isEmpty);
    expect(_seqs(jb.drain(1000 + 50000)), [1]); // aged → released
  });

  test('force-skips oldest gap when buffer exceeds maxPackets', () {
    final jb = JitterBuffer(
        config: const JitterBufferConfig(
            playoutDelay: 0, gapTimeout: 1 << 30, maxPackets: 4));
    // seq 1 missing; fill 2..6 (5 packets > maxPackets=4) so overflow forces
    // playout to start at the oldest buffered (seq 2) despite the huge timeout.
    for (var s = 2; s <= 6; s++) {
      jb.add(_pkt(s), 1000);
    }
    expect(_seqs(jb.drain(1000)), [2, 3, 4, 5, 6]);
  });

  test('flush returns remaining packets in order and empties', () {
    final jb = JitterBuffer(config: noDelay);
    jb.add(_pkt(5), 1000);
    jb.add(_pkt(7), 1000);
    expect(_seqs(jb.flush()), [5, 7]);
    expect(jb.length, 0);
  });
}
