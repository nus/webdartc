@Tags(['native'])
@TestOn('!mac-os')
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/codec/vp8/vp8_encoder_backend.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/rtp/packetizer.dart';

void main() {
  setUpAll(registerVp8Codec);

  test('encoder → packetizer → depacketizer reassembles byte-identical '
      'frames and agrees on key/delta classification', () async {
    const width = 320, height = 240, frames = 8;

    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('encoder error: $e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'vp8',
      width: width,
      height: height,
      bitrate: 400000,
      framerate: 30,
    ));

    final src = FakeVideoSource(width: width, height: height, framerate: 30);
    const forcedKeyframeOnFrame = 4;
    for (var i = 0; i < frames; i++) {
      final frame = src.frameAt(1_700_000_000_000 + i * 33);
      encoder.encode(
        frame,
        VideoEncoderEncodeOptions(keyFrame: i == forcedKeyframeOnFrame),
      );
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, hasLength(frames));

    // Round-trip each chunk through packetizer + depacketizer.
    final packetizer = Vp8Packetizer(maxPayloadSize: 300); // small MTU → force fragmentation
    final depacketizer = Vp8Depacketizer();
    final reassembled = <EncodedVideoChunk>[];

    for (final src in chunks) {
      final parts = packetizer.packetize(
        src.data,
        isKeyFrame: src.type == EncodedVideoChunkType.key,
      );
      expect(parts, isNotEmpty);
      expect(parts.last.$2, isTrue, reason: 'last fragment must carry marker');
      // Only the final fragment has marker=true — everything else is false.
      for (var i = 0; i < parts.length - 1; i++) {
        expect(parts[i].$2, isFalse);
      }
      EncodedVideoChunk? assembled;
      for (final (payload, marker) in parts) {
        final out = depacketizer.depacketize(
          payload,
          marker: marker,
          timestamp: src.timestamp,
        );
        if (out != null) assembled = out;
      }
      expect(assembled, isNotNull);
      reassembled.add(assembled!);
    }

    for (var i = 0; i < chunks.length; i++) {
      expect(reassembled[i].data, chunks[i].data,
          reason: 'frame $i bytes must match exactly');
      expect(reassembled[i].type, chunks[i].type,
          reason: 'frame $i key/delta classification must match');
      expect(reassembled[i].timestamp, chunks[i].timestamp);
    }

    // Frame 0 is always a keyframe; frame 4 was forced.
    expect(chunks[0].type, EncodedVideoChunkType.key);
    expect(chunks[forcedKeyframeOnFrame].type, EncodedVideoChunkType.key);
  });

  test('single-fragment packet still sets marker=true and depacketizes', () {
    final packetizer = Vp8Packetizer(maxPayloadSize: 8192);
    final depacketizer = Vp8Depacketizer();
    // Synthetic keyframe-looking VP8 bytes (first byte bit 0 = 0).
    final fake = List<int>.generate(100, (i) => i & 0xFE);
    final parts = packetizer.packetize(
      // ignore: prefer_const_constructors, prefer_const_literals_to_create_immutables
      Uint8List.fromList(fake),
      isKeyFrame: true,
    );
    expect(parts, hasLength(1));
    expect(parts[0].$2, isTrue);

    final chunk = depacketizer.depacketize(
      parts[0].$1,
      marker: true,
      timestamp: 99,
    );
    expect(chunk, isNotNull);
    expect(chunk!.data.length, 100);
    expect(chunk.type, EncodedVideoChunkType.key);
  });
}
