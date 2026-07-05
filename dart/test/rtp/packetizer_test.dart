import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/codec/codec_support.dart';
import 'package:webdartc/src/codec/video_codec.dart';
import 'package:webdartc/src/codec/audio_codec.dart';
import 'package:webdartc/src/rtp/packetizer.dart';

void main() {
  group('Vp8Packetizer', () {
    test('small frame fits in single packet', () {
      final packetizer = Vp8Packetizer(maxPayloadSize: 1200);
      final frame = Uint8List.fromList(List.generate(100, (i) => i & 0xFF));
      final packets = packetizer.packetize(frame, isKeyFrame: true);

      expect(packets.length, equals(1));
      expect(packets[0].$2, isTrue); // marker
      // First byte is VP8 descriptor with S=1
      expect(packets[0].$1[0] & 0x10, equals(0x10));
      // Payload follows descriptor
      expect(packets[0].$1.length, equals(101)); // 1 descriptor + 100 data
    });

    test('large frame is fragmented', () {
      final packetizer = Vp8Packetizer(maxPayloadSize: 100);
      final frame = Uint8List.fromList(List.generate(250, (i) => i & 0xFF));
      final packets = packetizer.packetize(frame, isKeyFrame: false);

      expect(packets.length, equals(3)); // 99+99+52 = 250
      // First fragment: S=1, marker=false
      expect(packets[0].$1[0] & 0x10, equals(0x10));
      expect(packets[0].$2, isFalse);
      // Middle fragment: S=0, marker=false
      expect(packets[1].$1[0] & 0x10, equals(0x00));
      expect(packets[1].$2, isFalse);
      // Last fragment: S=0, marker=true
      expect(packets[2].$1[0] & 0x10, equals(0x00));
      expect(packets[2].$2, isTrue);
    });

    test('empty frame returns empty list', () {
      final packetizer = Vp8Packetizer();
      expect(packetizer.packetize(Uint8List(0), isKeyFrame: true), isEmpty);
    });
  });

  group('Vp8Depacketizer', () {
    test('single packet depacketizes immediately', () {
      final depacketizer = Vp8Depacketizer();
      // VP8 keyframe: descriptor S=1 (0x10), then payload with bit0=0 (keyframe)
      final payload = Uint8List.fromList([0x10, 0x00, 0x01, 0x02]);
      final chunk = depacketizer.depacketize(payload, marker: true, timestamp: 1000);

      expect(chunk, isNotNull);
      expect(chunk!.type, equals(EncodedVideoChunkType.key));
      expect(chunk.timestamp, equals(1000));
      expect(chunk.data.length, equals(3)); // payload after descriptor
    });

    test('multi-fragment reassembly', () {
      final depacketizer = Vp8Depacketizer();

      // Fragment 1: S=1, marker=false
      final frag1 = Uint8List.fromList([0x10, 0x00, 0xAA, 0xBB]);
      expect(depacketizer.depacketize(frag1, marker: false, timestamp: 2000), isNull);

      // Fragment 2: S=0, marker=true
      final frag2 = Uint8List.fromList([0x00, 0xCC, 0xDD]);
      final chunk = depacketizer.depacketize(frag2, marker: true, timestamp: 2000);

      expect(chunk, isNotNull);
      expect(chunk!.data.length, equals(5)); // 3 + 2 bytes
      expect(chunk.data, equals(Uint8List.fromList([0x00, 0xAA, 0xBB, 0xCC, 0xDD])));
    });

    test('delta frame detection', () {
      final depacketizer = Vp8Depacketizer();
      // VP8 delta: descriptor S=1, then payload with bit0=1
      final payload = Uint8List.fromList([0x10, 0x01, 0x02, 0x03]);
      final chunk = depacketizer.depacketize(payload, marker: true, timestamp: 3000);

      expect(chunk, isNotNull);
      expect(chunk!.type, equals(EncodedVideoChunkType.delta));
    });
  });

  group('Vp8 round-trip', () {
    test('packetize then depacketize recovers original data', () {
      final packetizer = Vp8Packetizer(maxPayloadSize: 50);
      final depacketizer = Vp8Depacketizer();

      // Original VP8 keyframe data (bit0=0)
      final original = Uint8List.fromList([0x00, ...List.generate(120, (i) => (i + 1) & 0xFF)]);
      final packets = packetizer.packetize(original, isKeyFrame: true);

      expect(packets.length, greaterThan(1)); // should be fragmented

      EncodedVideoChunk? result;
      for (final (payload, marker) in packets) {
        result = depacketizer.depacketize(payload, marker: marker, timestamp: 5000);
      }

      expect(result, isNotNull);
      expect(result!.type, equals(EncodedVideoChunkType.key));
      expect(result.data, equals(original));
    });
  });

  group('Vp9Packetizer', () {
    test('keyframe single packet has I/F/B/E set, P/V clear', () {
      final packetizer = Vp9Packetizer(maxPayloadSize: 1200);
      final frame = Uint8List.fromList(List.generate(100, (i) => i & 0xFF));
      final packets = packetizer.packetize(frame, isKeyFrame: true);

      expect(packets.length, equals(1));
      expect(packets[0].$2, isTrue); // marker
      final p = packets[0].$1;
      // I=1, P=0, L=0, F=1, B=1, E=1, V=0, Z=0
      expect(p[0], equals(0x80 | 0x10 | 0x08 | 0x04));
      expect(p[1] & 0x80, equals(0x80)); // M=1: 15-bit picture ID
      expect(p.length, equals(3 + 100)); // 3-byte descriptor + data
    });

    test('delta frame has P set and one P_DIFF byte', () {
      final packetizer = Vp9Packetizer();
      final frame = Uint8List.fromList([0x01, 0x02, 0x03]);
      final packets = packetizer.packetize(frame, isKeyFrame: false);

      expect(packets.length, equals(1));
      final p = packets[0].$1;
      expect(p[0] & 0x40, equals(0x40)); // P=1
      expect(p[3], equals(0x02)); // P_DIFF=1, N=0
      expect(p.sublist(4), equals(frame));
    });

    test('fragmentation: B on first, E+marker on last, shared picture ID',
        () {
      final packetizer = Vp9Packetizer(maxPayloadSize: 100);
      final frame = Uint8List.fromList(List.generate(250, (i) => i & 0xFF));
      final packets = packetizer.packetize(frame, isKeyFrame: true);

      expect(packets.length, equals(3)); // 97+97+56
      expect(packets[0].$1[0] & 0x08, equals(0x08)); // B
      expect(packets[0].$1[0] & 0x04, equals(0x00));
      expect(packets[0].$2, isFalse);
      expect(packets[1].$1[0] & 0x0C, equals(0x00)); // neither B nor E
      expect(packets[1].$2, isFalse);
      expect(packets[2].$1[0] & 0x08, equals(0x00));
      expect(packets[2].$1[0] & 0x04, equals(0x04)); // E
      expect(packets[2].$2, isTrue);
      for (final (p, _) in packets) {
        expect(p[1], equals(packets[0].$1[1]));
        expect(p[2], equals(packets[0].$1[2]));
      }
    });

    test('picture ID increments once per frame (mod 2^15)', () {
      final packetizer = Vp9Packetizer();
      int pidOf(List<(Uint8List, bool)> packets) =>
          ((packets[0].$1[1] & 0x7F) << 8) | packets[0].$1[2];
      final pid1 =
          pidOf(packetizer.packetize(Uint8List(10), isKeyFrame: true));
      final pid2 =
          pidOf(packetizer.packetize(Uint8List(10), isKeyFrame: false));
      expect(pid2, equals((pid1 + 1) & 0x7FFF));
    });

    test('empty frame returns empty list', () {
      expect(Vp9Packetizer().packetize(Uint8List(0), isKeyFrame: true),
          isEmpty);
    });
  });

  group('Vp9Depacketizer', () {
    test('Chrome-style non-flexible keyframe with SS (Y+G) parses', () {
      final depacketizer = Vp9Depacketizer();
      final payload = Uint8List.fromList([
        0x80 | 0x20 | 0x08 | 0x04 | 0x02, // I, L, B, E, V (P=0, F=0)
        0x80 | 0x12, 0x34, // 15-bit picture ID
        0x00, // TID/U/SID/D
        0x00, // TL0PICIDX (non-flexible mode)
        0x18, // SS: N_S=0, Y=1, G=1
        0x01, 0x40, 0x00, 0xF0, // 320x240
        0x01, // N_G=1
        0x04, // group: T=0, U=0, R=1
        0x01, // P_DIFF
        0xDE, 0xAD, // VP9 payload
      ]);
      final chunk =
          depacketizer.depacketize(payload, marker: true, timestamp: 1000);

      expect(chunk, isNotNull);
      expect(chunk!.type, equals(EncodedVideoChunkType.key));
      expect(chunk.data, equals(Uint8List.fromList([0xDE, 0xAD])));
    });

    test('non-flexible delta frame with layer indices parses', () {
      final depacketizer = Vp9Depacketizer();
      final payload = Uint8List.fromList([
        0x80 | 0x40 | 0x20 | 0x08 | 0x04, // I, P, L, B, E (F=0)
        0x80 | 0x00, 0x07, // picture ID
        0x00, 0x05, // layer indices + TL0PICIDX
        0x01, 0x02, 0x03, // payload
      ]);
      final chunk =
          depacketizer.depacketize(payload, marker: true, timestamp: 2000);

      expect(chunk, isNotNull);
      expect(chunk!.type, equals(EncodedVideoChunkType.delta));
      expect(chunk.data, equals(Uint8List.fromList([0x01, 0x02, 0x03])));
    });

    test('flexible mode with chained P_DIFFs parses', () {
      final depacketizer = Vp9Depacketizer();
      final payload = Uint8List.fromList([
        0x80 | 0x40 | 0x10 | 0x08 | 0x04, // I, P, F, B, E
        0x80, 0x01, // picture ID
        0x03, 0x05, 0x06, // 3 P_DIFFs (N set on first two)
        0xAA, 0xBB, // payload
      ]);
      final chunk =
          depacketizer.depacketize(payload, marker: true, timestamp: 3000);

      expect(chunk, isNotNull);
      expect(chunk!.data, equals(Uint8List.fromList([0xAA, 0xBB])));
    });

    test('padding packet (descriptor only) does not disturb a frame', () {
      final depacketizer = Vp9Depacketizer();
      // Keyframe first fragment
      final frag1 = Uint8List.fromList([0x98, 0x80, 0x01, 0x11]); // I,F,B
      expect(depacketizer.depacketize(frag1, marker: false, timestamp: 4000),
          isNull);
      // Bandwidth probe: full descriptor, empty payload
      final probe = Uint8List.fromList([0xDC, 0x80, 0x02, 0x02]);
      expect(depacketizer.depacketize(probe, marker: false, timestamp: 4000),
          isNull);
      // Final fragment: frame completes and is still a keyframe
      final frag2 = Uint8List.fromList([0x94, 0x80, 0x01, 0x22]); // I,F,E
      final chunk =
          depacketizer.depacketize(frag2, marker: true, timestamp: 4000);
      expect(chunk, isNotNull);
      expect(chunk!.type, equals(EncodedVideoChunkType.key));
      expect(chunk.data, equals(Uint8List.fromList([0x11, 0x22])));
    });

    test('truncated descriptors return null', () {
      expect(
          Vp9Depacketizer().depacketize(Uint8List.fromList([0x80]),
              marker: true, timestamp: 0),
          isNull); // I set, picture ID missing
      expect(
          Vp9Depacketizer().depacketize(
              Uint8List.fromList([0x02, 0x18, 0x01]), // V set, SS truncated
              marker: true,
              timestamp: 0),
          isNull);
      expect(
          Vp9Depacketizer()
              .depacketize(Uint8List(0), marker: true, timestamp: 0),
          isNull);
    });
  });

  group('Vp9 round-trip', () {
    test('packetize then depacketize recovers original data', () {
      final packetizer = Vp9Packetizer(maxPayloadSize: 50);
      final depacketizer = Vp9Depacketizer();

      final original =
          Uint8List.fromList(List.generate(121, (i) => (i * 7) & 0xFF));
      final packets = packetizer.packetize(original, isKeyFrame: true);
      expect(packets.length, greaterThan(1));

      EncodedVideoChunk? result;
      for (final (payload, marker) in packets) {
        result =
            depacketizer.depacketize(payload, marker: marker, timestamp: 5000);
      }

      expect(result, isNotNull);
      expect(result!.type, equals(EncodedVideoChunkType.key));
      expect(result.data, equals(original));

      // Delta frame round-trip through the same instances.
      final delta = Uint8List.fromList(List.generate(60, (i) => i & 0xFF));
      EncodedVideoChunk? deltaResult;
      for (final (payload, marker)
          in packetizer.packetize(delta, isKeyFrame: false)) {
        deltaResult =
            depacketizer.depacketize(payload, marker: marker, timestamp: 8000);
      }
      expect(deltaResult, isNotNull);
      expect(deltaResult!.type, equals(EncodedVideoChunkType.delta));
      expect(deltaResult.data, equals(delta));
    });
  });

  group('packetizer/depacketizer factories', () {
    test('cover vp8, vp9 and h264', () {
      expect(videoPacketizerFor('vp8'), isA<Vp8Packetizer>());
      expect(videoPacketizerFor('vp9'), isA<Vp9Packetizer>());
      expect(videoPacketizerFor('h264'), isA<H264Packetizer>());
      expect(videoPacketizerFor('av1'), isNull);
      expect(videoDepacketizerFor('vp9'), isA<Vp9Depacketizer>());
    });
  });

  group('OpusPacketizer', () {
    test('single frame per packet', () {
      final packetizer = OpusPacketizer();
      final frame = Uint8List.fromList([0xF8, 0xFF, 0xFE]); // Opus silence
      final packets = packetizer.packetize(frame, isKeyFrame: true);

      expect(packets.length, equals(1));
      expect(packets[0].$2, isTrue); // marker always true
      expect(packets[0].$1, equals(frame));
    });

    test('empty frame returns empty', () {
      expect(OpusPacketizer().packetize(Uint8List(0), isKeyFrame: true), isEmpty);
    });
  });

  group('OpusDepacketizer', () {
    test('depacketizes single packet', () {
      final depacketizer = OpusDepacketizer();
      final payload = Uint8List.fromList([0xF8, 0xFF, 0xFE]);
      final chunk = depacketizer.depacketize(payload, timestamp: 48000);

      expect(chunk, isNotNull);
      expect(chunk!.type, equals(EncodedAudioChunkType.key));
      expect(chunk.data, equals(payload));
      expect(chunk.timestamp, equals(48000));
    });

    test('empty payload returns null', () {
      expect(OpusDepacketizer().depacketize(Uint8List(0), timestamp: 0), isNull);
    });
  });

  group('Opus round-trip', () {
    test('packetize then depacketize recovers original', () {
      final packetizer = OpusPacketizer();
      final depacketizer = OpusDepacketizer();

      final original = Uint8List.fromList(List.generate(80, (i) => i));
      final packets = packetizer.packetize(original, isKeyFrame: true);

      expect(packets.length, equals(1));
      final chunk = depacketizer.depacketize(packets[0].$1, timestamp: 960);

      expect(chunk, isNotNull);
      expect(chunk!.data, equals(original));
    });
  });
}
