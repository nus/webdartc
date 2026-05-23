/// RFC 2435 JPEG (MJPEG) RTP packetizer / depacketizer round-trip tests.
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/rtp/packetizer.dart';

void main() {
  group('JpegPacketizer (RFC 2435)', () {
    test('small frame fits in single packet with marker=true', () {
      final jpeg = _makeBaselineJpeg(
          width: 64, height: 32, sampling: _Sampling.yuv422, entropyLen: 200);
      final pk = JpegPacketizer(maxPayloadSize: 1200);
      final pkts = pk.packetize(jpeg, isKeyFrame: true);
      expect(pkts, hasLength(1));
      expect(pkts[0].$2, isTrue);
      // First 8 bytes: main JPEG/RTP header
      final p = pkts[0].$1;
      expect(p[0], 0); // type-specific
      expect((p[1] << 16) | (p[2] << 8) | p[3], 0); // fragment offset = 0
      expect(p[4], 0); // type=0 (4:2:2)
      expect(p[5], 255); // Q=255 dynamic tables
      expect(p[6], 64 ~/ 8); // width units
      expect(p[7], 32 ~/ 8); // height units
    });

    test('4:2:0 frame reports Type=1', () {
      final jpeg = _makeBaselineJpeg(
          width: 64, height: 64, sampling: _Sampling.yuv420, entropyLen: 100);
      final pk = JpegPacketizer();
      final pkts = pk.packetize(jpeg, isKeyFrame: true);
      expect(pkts[0].$1[4], 1);
    });

    test('large frame is fragmented; only last carries marker', () {
      // Force fragmentation: entropy data well above maxPayloadSize.
      final jpeg = _makeBaselineJpeg(
          width: 64, height: 64, sampling: _Sampling.yuv422, entropyLen: 3000);
      final pk = JpegPacketizer(maxPayloadSize: 400);
      final pkts = pk.packetize(jpeg, isKeyFrame: true);
      expect(pkts.length, greaterThan(1));
      for (var i = 0; i < pkts.length - 1; i++) {
        expect(pkts[i].$2, isFalse, reason: 'middle packet $i must not mark');
      }
      expect(pkts.last.$2, isTrue);
      // Fragment offsets are strictly increasing and match payload sizes.
      var expected = 0;
      for (var i = 0; i < pkts.length; i++) {
        final p = pkts[i].$1;
        final fo = (p[1] << 16) | (p[2] << 8) | p[3];
        expect(fo, expected, reason: 'packet $i fragment offset');
        // First packet carries 8 main + 4+128 QT = 140 byte header.
        final headerLen = i == 0 ? 8 + 4 + 128 : 8;
        expected += p.length - headerLen;
      }
    });

    test('first packet emits Quantization Table header', () {
      final jpeg = _makeBaselineJpeg(
          width: 16, height: 16, sampling: _Sampling.yuv422, entropyLen: 32);
      final pk = JpegPacketizer();
      final pkts = pk.packetize(jpeg, isKeyFrame: true);
      final p = pkts.first.$1;
      // After 8-byte main header: MBZ=0, Precision=0, Length=128, then 128 bytes
      expect(p[8], 0);
      expect(p[9], 0);
      expect((p[10] << 8) | p[11], 128);
      // The two tables should be the standard JPEG luma + chroma quant
      // tables we put into the synthesised JPEG.
      expect(p.sublist(12, 76), equals(_lumaQuantTable));
      expect(p.sublist(76, 140), equals(_chromaQuantTable));
    });

    test('Restart Marker header emitted only with DRI', () {
      final withDri = _makeBaselineJpeg(
          width: 64,
          height: 64,
          sampling: _Sampling.yuv422,
          entropyLen: 100,
          restartInterval: 8);
      final noDri = _makeBaselineJpeg(
          width: 64,
          height: 64,
          sampling: _Sampling.yuv422,
          entropyLen: 100);
      final pk = JpegPacketizer();

      final withPkts = pk.packetize(withDri, isKeyFrame: true).first.$1;
      // Type=0+64 when DRI is present
      expect(withPkts[4], 64);
      // 4-byte RST header right after the 8-byte main header.
      expect((withPkts[8] << 8) | withPkts[9], 8);
      expect(withPkts[10], 0xFF); // F=1 L=1 + top of count
      expect(withPkts[11], 0xFF);
      // Then the QT header follows (MBZ=0, Precision=0, Length=128).
      expect(withPkts[12], 0);
      expect(withPkts[13], 0);
      expect((withPkts[14] << 8) | withPkts[15], 128);

      final withoutPkts = pk.packetize(noDri, isKeyFrame: true).first.$1;
      expect(withoutPkts[4], 0);
      // No RST header — QT header starts immediately after main header.
      expect(withoutPkts[8], 0);
      expect(withoutPkts[9], 0);
      expect((withoutPkts[10] << 8) | withoutPkts[11], 128);
    });

    test('empty frame returns empty list', () {
      expect(JpegPacketizer().packetize(Uint8List(0), isKeyFrame: true),
          isEmpty);
    });

    test('rejects non-baseline JPEG', () {
      final jpeg = _makeBaselineJpeg(
          width: 16, height: 16, sampling: _Sampling.yuv422, entropyLen: 32);
      // Flip SOF0 (FFC0) → SOF2 (FFC2, progressive).
      final corrupted = Uint8List.fromList(jpeg);
      for (var i = 0; i < corrupted.length - 1; i++) {
        if (corrupted[i] == 0xFF && corrupted[i + 1] == 0xC0) {
          corrupted[i + 1] = 0xC2;
          break;
        }
      }
      expect(() => JpegPacketizer().packetize(corrupted, isKeyFrame: true),
          throwsArgumentError);
    });
  });

  group('JpegDepacketizer (RFC 2435)', () {
    test('round-trips a single-packet frame', () {
      final src = _makeBaselineJpeg(
          width: 80, height: 48, sampling: _Sampling.yuv422, entropyLen: 200);
      final pk = JpegPacketizer();
      final pkts = pk.packetize(src, isKeyFrame: true);
      final depack = JpegDepacketizer();
      EncodedVideoChunk? out;
      for (var i = 0; i < pkts.length; i++) {
        final chunk = depack.depacketize(pkts[i].$1,
            marker: pkts[i].$2, timestamp: 12345);
        if (i < pkts.length - 1) {
          expect(chunk, isNull);
        } else {
          out = chunk;
        }
      }
      expect(out, isNotNull);
      expect(out!.type, EncodedVideoChunkType.key);
      expect(out.timestamp, 12345);
      _expectValidJpeg(out.data, expectedWidth: 80, expectedHeight: 48,
          expectedSampling: _Sampling.yuv422);
    });

    test('round-trips a fragmented frame', () {
      final src = _makeBaselineJpeg(
          width: 128, height: 96, sampling: _Sampling.yuv420, entropyLen: 4500);
      final pk = JpegPacketizer(maxPayloadSize: 400);
      final pkts = pk.packetize(src, isKeyFrame: true);
      expect(pkts.length, greaterThan(5));
      final depack = JpegDepacketizer();
      EncodedVideoChunk? out;
      for (final (payload, marker) in pkts) {
        final c = depack.depacketize(payload, marker: marker, timestamp: 99);
        if (c != null) out = c;
      }
      expect(out, isNotNull);
      _expectValidJpeg(out!.data, expectedWidth: 128, expectedHeight: 96,
          expectedSampling: _Sampling.yuv420);
    });

    test('preserves entropy bytes verbatim across the round-trip', () {
      // Build a JPEG with a distinctive entropy payload, then verify the
      // reassembled JPEG's SOS..EOI window contains the same bytes.
      final src = _makeBaselineJpeg(
          width: 32,
          height: 32,
          sampling: _Sampling.yuv422,
          entropyLen: 250,
          entropyFill: (i) => (i * 31 + 7) & 0xFF);
      final pk = JpegPacketizer(maxPayloadSize: 200);
      final pkts = pk.packetize(src, isKeyFrame: true);
      final depack = JpegDepacketizer();
      EncodedVideoChunk? out;
      for (final (payload, marker) in pkts) {
        final c = depack.depacketize(payload, marker: marker, timestamp: 1);
        if (c != null) out = c;
      }
      final reassembled = out!.data;
      // Locate the entropy segment in both bitstreams (after SOS header,
      // up to EOI) and verify byte-for-byte equality.
      final srcEntropy = _extractEntropy(src);
      final reEntropy = _extractEntropy(reassembled);
      expect(reEntropy, equals(srcEntropy));
    });

    test('drops a frame when a middle fragment is lost', () {
      final src = _makeBaselineJpeg(
          width: 64, height: 64, sampling: _Sampling.yuv422, entropyLen: 2000);
      final pk = JpegPacketizer(maxPayloadSize: 400);
      final pkts = pk.packetize(src, isKeyFrame: true);
      expect(pkts.length, greaterThan(3));
      final depack = JpegDepacketizer();
      // Drop packet index 1
      for (var i = 0; i < pkts.length; i++) {
        if (i == 1) continue;
        final c = depack.depacketize(pkts[i].$1,
            marker: pkts[i].$2, timestamp: 0);
        if (pkts[i].$2) {
          // marker arrived but reassembly was abandoned → null
          expect(c, isNull);
        }
      }
    });

    test('recovers on next frame after a drop', () {
      final srcA = _makeBaselineJpeg(
          width: 32, height: 32, sampling: _Sampling.yuv422, entropyLen: 1000);
      final srcB = _makeBaselineJpeg(
          width: 48, height: 32, sampling: _Sampling.yuv422, entropyLen: 800);
      final pk = JpegPacketizer(maxPayloadSize: 300);
      final depack = JpegDepacketizer();

      // Frame A: drop packet 1 → no chunk
      final aPkts = pk.packetize(srcA, isKeyFrame: true);
      for (var i = 0; i < aPkts.length; i++) {
        if (i == 1) continue;
        depack.depacketize(aPkts[i].$1, marker: aPkts[i].$2, timestamp: 100);
      }
      // Frame B: deliver all → should still produce a valid JPEG.
      final bPkts = pk.packetize(srcB, isKeyFrame: true);
      EncodedVideoChunk? out;
      for (final (payload, marker) in bPkts) {
        final c = depack.depacketize(payload, marker: marker, timestamp: 200);
        if (c != null) out = c;
      }
      expect(out, isNotNull);
      _expectValidJpeg(out!.data, expectedWidth: 48, expectedHeight: 32,
          expectedSampling: _Sampling.yuv422);
    });
  });
}

// ── Test helpers: synthesize a minimal baseline JPEG ────────────────────────

enum _Sampling { yuv422, yuv420 }

// JPEG Annex K Table K.1 — standard 50% quality luminance quantization
// table in zig-zag order, used here so the round-trip tests can compare
// against a known byte sequence.
const List<int> _lumaQuantTable = [
  16, 11, 12, 14, 12, 10, 16, 14, 13, 14, 18, 17, 16, 19, 24, 40,
  26, 24, 22, 22, 24, 49, 35, 37, 29, 40, 58, 51, 61, 60, 57, 51,
  56, 55, 64, 72, 92, 78, 64, 68, 87, 69, 55, 56, 80, 109, 81, 87,
  95, 98, 103, 104, 103, 62, 77, 113, 121, 112, 100, 120, 92, 101, 103, 99,
];
const List<int> _chromaQuantTable = [
  17, 18, 18, 24, 21, 24, 47, 26, 26, 47, 99, 66, 56, 66, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

/// Builds a minimal but spec-conformant baseline JFIF JPEG with the given
/// dimensions and chroma subsampling. The entropy data is arbitrary
/// "looks like coefficients" bytes (no internal markers — every 0xFF is
/// escaped with 0x00) so the parser's marker-scan path is exercised.
Uint8List _makeBaselineJpeg({
  required int width,
  required int height,
  required _Sampling sampling,
  required int entropyLen,
  int? restartInterval,
  int Function(int i)? entropyFill,
}) {
  final b = BytesBuilder(copy: false);
  // SOI
  b.add([0xFF, 0xD8]);
  // DQT (Y + C, 8-bit, dest 0 / 1)
  b.add([0xFF, 0xDB, 0x00, 2 + 2 * 65]);
  b.addByte(0x00);
  b.add(_lumaQuantTable);
  b.addByte(0x01);
  b.add(_chromaQuantTable);
  // DRI (optional)
  if (restartInterval != null) {
    b.add([0xFF, 0xDD, 0x00, 0x04]);
    b.addByte((restartInterval >> 8) & 0xFF);
    b.addByte(restartInterval & 0xFF);
  }
  // SOF0
  b.add([0xFF, 0xC0, 0x00, 8 + 3 * 3, 8]);
  b.add([(height >> 8) & 0xFF, height & 0xFF]);
  b.add([(width >> 8) & 0xFF, width & 0xFF]);
  b.addByte(3);
  final yHv = sampling == _Sampling.yuv422 ? 0x21 : 0x22;
  b.add([1, yHv, 0]);
  b.add([2, 0x11, 1]);
  b.add([3, 0x11, 1]);
  // DHT × 4 — use trivial dummy tables; the depacketizer overwrites them
  // with the standard Annex K tables anyway, so contents are irrelevant
  // to the round-trip assertions. We just need the segments to be
  // syntactically valid so the JPEG parses end-to-end.
  for (final (tc, th) in [(0, 0), (1, 0), (0, 1), (1, 1)]) {
    b.add([0xFF, 0xC4, 0x00, 2 + 1 + 16 + 1]);
    b.addByte((tc << 4) | (th & 0x0F));
    // 16 zero BITS entries + 1 dummy symbol.
    for (var i = 0; i < 16; i++) {
      b.addByte(0);
    }
    b.addByte(0);
  }
  // SOS
  b.add([0xFF, 0xDA, 0x00, 6 + 3 * 2, 3]);
  b.add([1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
  // Entropy data — fill with arbitrary bytes, escaping any 0xFF.
  final fill = entropyFill ?? ((i) => (i * 13) & 0xFE); // never 0xFF by default
  for (var i = 0; i < entropyLen; i++) {
    final v = fill(i);
    b.addByte(v);
    if (v == 0xFF) b.addByte(0x00); // JPEG byte-stuffing
  }
  // EOI
  b.add([0xFF, 0xD9]);
  return b.takeBytes();
}

/// Asserts that [jpeg] starts with SOI, ends with EOI, and that its SOF0
/// reports the expected dimensions and sampling.
void _expectValidJpeg(Uint8List jpeg, {
  required int expectedWidth,
  required int expectedHeight,
  required _Sampling expectedSampling,
}) {
  expect(jpeg.length, greaterThan(20));
  expect([jpeg[0], jpeg[1]], [0xFF, 0xD8]);
  expect([jpeg[jpeg.length - 2], jpeg[jpeg.length - 1]], [0xFF, 0xD9]);

  // Walk markers to find SOF0.
  var i = 2;
  while (i + 3 < jpeg.length) {
    if (jpeg[i] != 0xFF) {
      fail('Expected marker at offset $i, got 0x${jpeg[i].toRadixString(16)}');
    }
    final marker = jpeg[i + 1];
    i += 2;
    if (marker == 0xD8 || marker == 0xD9 ||
        marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
      continue;
    }
    final segLen = (jpeg[i] << 8) | jpeg[i + 1];
    if (marker == 0xC0) {
      // SOF0
      final precision = jpeg[i + 2];
      final h = (jpeg[i + 3] << 8) | jpeg[i + 4];
      final w = (jpeg[i + 5] << 8) | jpeg[i + 6];
      expect(precision, 8);
      expect(w, expectedWidth);
      expect(h, expectedHeight);
      final yHv = jpeg[i + 9];
      final expectedHv = expectedSampling == _Sampling.yuv422 ? 0x21 : 0x22;
      expect(yHv, expectedHv);
      return;
    }
    if (marker == 0xDA) break; // SOS — entropy follows, no more headers
    i += segLen;
  }
  fail('Reassembled JPEG missing SOF0');
}

/// Extracts the entropy-coded segment (bytes between SOS header end and
/// the EOI marker). Used by the round-trip test to compare what the
/// camera fed in versus what the depacketizer reassembled.
Uint8List _extractEntropy(Uint8List jpeg) {
  var i = 2;
  while (i + 3 < jpeg.length) {
    if (jpeg[i] != 0xFF) {
      fail('Bad JPEG: missing marker at $i');
    }
    final marker = jpeg[i + 1];
    i += 2;
    if (marker == 0xD8 || marker == 0xD9 ||
        marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
      continue;
    }
    final segLen = (jpeg[i] << 8) | jpeg[i + 1];
    if (marker == 0xDA) {
      // SOS — entropy stream starts right after the SOS header.
      final start = i + segLen;
      var end = start;
      while (end + 1 < jpeg.length) {
        if (jpeg[end] == 0xFF) {
          final next = jpeg[end + 1];
          if (next == 0x00 || (next >= 0xD0 && next <= 0xD7) || next == 0xFF) {
            end += 2;
            continue;
          }
          break;
        }
        end++;
      }
      return Uint8List.fromList(jpeg.sublist(start, end));
    }
    i += segLen;
  }
  fail('No SOS found in JPEG');
}
