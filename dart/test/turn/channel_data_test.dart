import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/turn/channel_data.dart';

void main() {
  group('ChannelData framing', () {
    test('build + parse round-trip', () {
      final payload =
          Uint8List.fromList(List<int>.generate(100, (i) => i & 0xFF));
      final frame = buildChannelData(0x4001, payload);
      expect(frame.length, 4 + payload.length);

      final parsed = parseChannelData(frame);
      expect(parsed?.channel, 0x4001);
      expect(parsed?.payload, payload);
    });

    test('build with padding rounds up to 4-byte boundary', () {
      final payload = Uint8List.fromList([1, 2, 3]);
      final padded = buildChannelData(0x4001, payload, pad: true);
      expect(padded.length, 4 + 4);

      final unpadded = buildChannelData(0x4001, payload);
      expect(unpadded.length, 4 + 3);
    });

    test('parse honours the length field even when buffer has trailing bytes',
        () {
      // 3 bytes of payload, 1 byte of pad, parse should return payload-only.
      final payload = Uint8List.fromList([1, 2, 3]);
      final padded = buildChannelData(0x4001, payload, pad: true);
      final parsed = parseChannelData(padded);
      expect(parsed?.payload.length, 3);
      expect(parsed?.payload, payload);
    });

    test('isChannelData distinguishes from STUN', () {
      // STUN message: first byte high 2 bits = 00.
      expect(isChannelData(Uint8List.fromList([0x00, 0x01, 0, 0])), isFalse);
      // ChannelData: first byte high 2 bits = 01 (channel 0x4000-0x7FFF).
      expect(isChannelData(Uint8List.fromList([0x40, 0x00, 0, 0])), isTrue);
      expect(isChannelData(Uint8List.fromList([0x7F, 0xFF, 0, 0])), isTrue);
      // Reserved: high 2 bits = 10/11.
      expect(isChannelData(Uint8List.fromList([0x80, 0x00, 0, 0])), isFalse);
    });

    test('isValidChannelNumber covers RFC 5766 §11 range', () {
      expect(isValidChannelNumber(0x3FFF), isFalse);
      expect(isValidChannelNumber(0x4000), isTrue);
      expect(isValidChannelNumber(0x7FFF), isTrue);
      expect(isValidChannelNumber(0x8000), isFalse);
    });

    test('build rejects out-of-range channel', () {
      expect(() => buildChannelData(0x3FFF, Uint8List(0)),
          throwsA(isA<ArgumentError>()));
      expect(() => buildChannelData(0x8000, Uint8List(0)),
          throwsA(isA<ArgumentError>()));
    });

    test('build rejects oversized payload', () {
      expect(() => buildChannelData(0x4001, Uint8List(0x10000)),
          throwsA(isA<ArgumentError>()));
    });

    test('parse rejects out-of-range channel', () {
      expect(parseChannelData(Uint8List.fromList([0x3F, 0xFF, 0, 0])), isNull);
      expect(parseChannelData(Uint8List.fromList([0x80, 0x00, 0, 0])), isNull);
    });

    test('parse rejects truncated frame', () {
      // Header claims 4-byte payload but only 3 follow.
      final truncated = Uint8List.fromList([0x40, 0x01, 0, 4, 1, 2, 3]);
      expect(parseChannelData(truncated), isNull);
    });

    test('parse rejects header-only buffer shorter than 4 bytes', () {
      expect(parseChannelData(Uint8List(3)), isNull);
    });
  });
}
