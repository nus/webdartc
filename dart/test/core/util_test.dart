import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/core/backoff.dart';
import 'package:webdartc/core/hex.dart';
import 'package:webdartc/crypto/constant_time.dart';

void main() {
  group('hex', () {
    test('lowercase, zero-padded, no separator by default', () {
      expect(hex([0x00, 0x0f, 0xab, 0xff]), '000fabff');
    });

    test('empty input', () {
      expect(hex(const []), '');
    });

    test('separator', () {
      expect(hex([0xde, 0xad], separator: ' '), 'de ad');
    });

    test('fingerprint format: uppercase + colon', () {
      expect(hex([0x0a, 0xb1, 0x5e], separator: ':', upperCase: true),
          '0A:B1:5E');
    });
  });

  group('ExponentialBackoff', () {
    test('doubles per attempt from base', () {
      const b = ExponentialBackoff(baseMs: 500, maxMs: 16000);
      expect(b.delayMs(0), 500);
      expect(b.delayMs(1), 1000);
      expect(b.delayMs(2), 2000);
      expect(b.delayMs(5), 16000);
    });

    test('clamps at maxMs', () {
      const b = ExponentialBackoff(baseMs: 500, maxMs: 16000);
      expect(b.delayMs(6), 16000);
      expect(b.delayMs(10), 16000);
    });

    test('protocol parameterizations match legacy timings', () {
      // DTLS flight retransmit: 500ms base, 60s cap.
      const dtls = ExponentialBackoff(baseMs: 500, maxMs: 60000);
      expect(dtls.delayMs(7), 60000);
      expect(dtls.delayMs(6), 32000);
      // SCTP T3-rtx: 3s base, 60s cap.
      const sctp = ExponentialBackoff(baseMs: 3000, maxMs: 60000);
      expect(sctp.delayMs(0), 3000);
      expect(sctp.delayMs(4), 48000);
      expect(sctp.delayMs(5), 60000);
    });
  });

  group('constantTimeEquals', () {
    Uint8List bytes(List<int> v) => Uint8List.fromList(v);

    test('equal buffers', () {
      expect(constantTimeEquals(bytes([1, 2, 3]), bytes([1, 2, 3])), isTrue);
      expect(constantTimeEquals(bytes([]), bytes([])), isTrue);
    });

    test('differing contents', () {
      expect(constantTimeEquals(bytes([1, 2, 3]), bytes([1, 2, 4])), isFalse);
      expect(constantTimeEquals(bytes([0x80]), bytes([0x00])), isFalse);
    });

    test('length mismatch', () {
      expect(constantTimeEquals(bytes([1, 2]), bytes([1, 2, 3])), isFalse);
    });
  });
}
