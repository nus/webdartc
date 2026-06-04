import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('DataChannelMessageEvent.text (RFC 8831 §6.6 UTF-8)', () {
    test('decodes multi-byte UTF-8 (emoji + Japanese)', () {
      const original = '🎉 日本語 café';
      final wire = Uint8List.fromList(utf8.encode(original));
      final evt = DataChannelMessageEvent(data: wire, isBinary: false);
      expect(evt.text, original);
    });

    test('round-trips through utf8.encode', () {
      for (final s in ['ascii', 'ümlaut', '한국어', '🚀🛰️', '']) {
        final evt = DataChannelMessageEvent(
          data: Uint8List.fromList(utf8.encode(s)),
          isBinary: false,
        );
        expect(evt.text, s, reason: 'round-trip "$s"');
      }
    });

    test('malformed UTF-8 is replaced, not thrown', () {
      // 0xFF is never a valid UTF-8 byte; decoding must not throw.
      final evt = DataChannelMessageEvent(
        data: Uint8List.fromList([0x41, 0xFF, 0x42]),
        isBinary: false,
      );
      expect(() => evt.text, returnsNormally);
      expect(evt.text, contains('A'));
      expect(evt.text, contains('B'));
    });
  });
}
