library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/rtp/packetizer.dart';

void main() {
  group('splitH264AnnexB', () {
    test('splits 3-byte start codes correctly', () {
      final data = Uint8List.fromList([
        0, 0, 1, 0x67, 0x42, 0xC0, 0x1F, // SPS
        0, 0, 1, 0x68, 0xCE, 0x38, 0x80, // PPS
        0, 0, 1, 0x65, 0x88, 0x84, 0x20, // IDR
      ]);
      final nals = splitH264AnnexB(data);
      expect(nals, hasLength(3));
      expect(nals[0][0], 0x67);
      expect(nals[1][0], 0x68);
      expect(nals[2][0], 0x65);
    });

    test('splits 4-byte start codes correctly', () {
      final data = Uint8List.fromList([
        0, 0, 0, 1, 0x67, 0x42,
        0, 0, 0, 1, 0x68, 0xCE,
        0, 0, 0, 1, 0x65, 0x88,
      ]);
      final nals = splitH264AnnexB(data);
      expect(nals, hasLength(3));
      expect(nals[0][0], 0x67);
    });

    test('handles mixed 3- and 4-byte start codes', () {
      final data = Uint8List.fromList([
        0, 0, 0, 1, 0x67, 0x42,
        0, 0, 1, 0x68, 0xCE,
      ]);
      final nals = splitH264AnnexB(data);
      expect(nals, hasLength(2));
      expect(nals[0][0], 0x67);
      expect(nals[1][0], 0x68);
    });
  });

  group('H264Packetizer', () {
    test('small single NAL produces one packet with marker=true', () {
      final packetizer = H264Packetizer();
      final nal = List<int>.filled(100, 0xAA);
      nal[0] = 0x65; // IDR NAL header
      final data = Uint8List.fromList([0, 0, 0, 1, ...nal]);
      final parts = packetizer.packetize(data, isKeyFrame: true);
      expect(parts, hasLength(1));
      expect(parts[0].$2, isTrue);
      expect(parts[0].$1[0], 0x65);
    });

    test('multiple small NALs → multiple single-NAL packets, only last '
        'carries marker', () {
      final packetizer = H264Packetizer();
      final data = Uint8List.fromList([
        0, 0, 0, 1, 0x67, 1, 2, 3,
        0, 0, 0, 1, 0x68, 4, 5,
        0, 0, 0, 1, 0x65, 6, 7, 8, 9,
      ]);
      final parts = packetizer.packetize(data, isKeyFrame: true);
      expect(parts, hasLength(3));
      expect(parts[0].$2, isFalse);
      expect(parts[1].$2, isFalse);
      expect(parts[2].$2, isTrue);
    });

    test('large NAL is fragmented into FU-A packets', () {
      final packetizer = H264Packetizer(maxPayloadSize: 100);
      // NAL body of 500 bytes + 1 header = 501 total; body split into ~98-byte chunks.
      final body = List<int>.generate(500, (i) => i & 0xFF);
      final header = 0x65; // IDR, NRI=3
      final data = Uint8List.fromList([0, 0, 0, 1, header, ...body]);
      final parts = packetizer.packetize(data, isKeyFrame: true);
      expect(parts.length, greaterThan(1));
      // First fragment: FU indicator type=28, FU header S=1.
      expect(parts.first.$1[0] & 0x1F, 28);
      expect(parts.first.$1[1] & 0x80, 0x80);
      // Last fragment: FU header E=1 and RTP marker=true.
      expect(parts.last.$1[0] & 0x1F, 28);
      expect(parts.last.$1[1] & 0x40, 0x40);
      expect(parts.last.$2, isTrue);
      // F/NRI preserved from original NAL header across FU indicator.
      expect(parts.first.$1[0] & 0xE0, header & 0xE0);
    });
  });

  group('H264Depacketizer', () {
    test('single NAL depacketizes to Annex B with 00 00 00 01 prefix', () {
      final depacketizer = H264Depacketizer();
      final chunk = depacketizer.depacketize(
        Uint8List.fromList([0x65, 0xAA, 0xBB]),
        marker: true,
        timestamp: 123,
      );
      expect(chunk, isNotNull);
      expect(chunk!.data, orderedEquals([0, 0, 0, 1, 0x65, 0xAA, 0xBB]));
      expect(chunk.type, EncodedVideoChunkType.key);
    });

    test('FU-A reassembly produces original NAL bytes', () {
      final depacketizer = H264Depacketizer();
      // Fragment 1: S=1, nalType=5 (IDR), NRI=3 from fuIndicator
      final p1 = Uint8List.fromList([0x7C, 0x85, 1, 2, 3]); // FU ind=0x7C (NRI=3|28), FU hdr=0x85 (S|type5)
      final p2 = Uint8List.fromList([0x7C, 0x05, 4, 5, 6]);
      final p3 = Uint8List.fromList([0x7C, 0x45, 7, 8, 9]);
      expect(depacketizer.depacketize(p1, marker: false, timestamp: 1), isNull);
      expect(depacketizer.depacketize(p2, marker: false, timestamp: 1), isNull);
      final chunk = depacketizer.depacketize(p3, marker: true, timestamp: 1);
      expect(chunk, isNotNull);
      // Expected NAL header: NRI from 0x7C (0x60) | type 5 = 0x65
      expect(chunk!.data,
          orderedEquals([0, 0, 0, 1, 0x65, 1, 2, 3, 4, 5, 6, 7, 8, 9]));
      expect(chunk.type, EncodedVideoChunkType.key);
    });

    test('non-IDR slice produces delta chunk', () {
      final depacketizer = H264Depacketizer();
      final chunk = depacketizer.depacketize(
        Uint8List.fromList([0x41, 0xAA]),
        marker: true,
        timestamp: 1,
      );
      expect(chunk!.type, EncodedVideoChunkType.delta);
    });
  });

  group('H264 round-trip packetize → depacketize', () {
    test('multi-NAL frame with one small + one fragmented NAL round-trips', () {
      final packetizer = H264Packetizer(maxPayloadSize: 50);
      final sps = [0x67, 0x42, 0xC0, 0x1F];
      final idrBody = List<int>.generate(200, (i) => (i * 3) & 0xFF);
      final idr = [0x65, ...idrBody];
      final annexB = Uint8List.fromList([
        0, 0, 0, 1, ...sps,
        0, 0, 0, 1, ...idr,
      ]);

      final parts = packetizer.packetize(annexB, isKeyFrame: true);
      expect(parts.length, greaterThan(1));

      final depacketizer = H264Depacketizer();
      EncodedVideoChunk? out;
      for (final (p, m) in parts) {
        final r = depacketizer.depacketize(p, marker: m, timestamp: 42);
        if (r != null) out = r;
      }
      expect(out, isNotNull);
      expect(out!.data, orderedEquals(annexB));
      expect(out.type, EncodedVideoChunkType.key);
      expect(out.timestamp, 42);
    });
  });
}
