import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/codec/audio_codec.dart';
import 'package:webdartc/rtp/packetizer.dart';

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
