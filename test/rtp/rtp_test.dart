import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('RtpParser', () {
    test('isRtcp: PT 200 is RTCP', () {
      final pkt = Uint8List(12);
      pkt[0] = 0x80;
      pkt[1] = 200 & 0x7F;
      expect(RtpParser.isRtcp(pkt), isTrue);
    });

    test('isRtcp: PT 96 is not RTCP', () {
      final pkt = Uint8List(12);
      pkt[0] = 0x80;
      pkt[1] = 96;
      expect(RtpParser.isRtcp(pkt), isFalse);
    });

    test('parseRtp round-trip', () {
      final original = RtpPacket(
        payloadType: 96,
        sequenceNumber: 1234,
        timestamp: 90000,
        ssrc: 0xDEADBEEF,
        payload: Uint8List.fromList([1, 2, 3, 4, 5]),
      );
      final raw = original.build();
      final parsed = RtpParser.parseRtp(raw);
      expect(parsed.isOk, isTrue);
      final pkt = parsed.value;
      expect(pkt.payloadType, equals(96));
      expect(pkt.sequenceNumber, equals(1234));
      expect(pkt.timestamp, equals(90000));
      expect(pkt.ssrc, equals(0xDEADBEEF));
      expect(pkt.payload, equals(Uint8List.fromList([1, 2, 3, 4, 5])));
    });

    test('parseRtp rejects version != 2', () {
      final pkt = Uint8List(12);
      pkt[0] = 0x40; // version=1
      expect(RtpParser.parseRtp(pkt).isErr, isTrue);
    });

    test('parseRtp rejects too-short packet', () {
      expect(RtpParser.parseRtp(Uint8List(8)).isErr, isTrue);
    });
  });
}
