@Tags(['native'])
@TestOn('mac-os')
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/codec_registry.dart';
import 'package:webdartc/codec/h264/videotoolbox_encoder_backend.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/rtp/packetizer.dart';

void main() {
  setUpAll(() {
    CodecRegistry.registerVideoEncoder('h264', VideoToolboxEncoderBackend.new);
  });

  test('first encoded frame is a keyframe with SPS/PPS/IDR Annex B', () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'h264',
      width: 160,
      height: 120,
      bitrate: 200000,
      framerate: 30,
    ));
    final src = FakeVideoSource(width: 160, height: 120, framerate: 30);
    for (var i = 0; i < 10; i++) {
      encoder.encode(src.frameAt(1000 + i));
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, isNotEmpty);
    expect(chunks.first.type, EncodedVideoChunkType.key);
    expect(chunks.first.data, isA<Uint8List>());
    final annexB = chunks.first.data;
    expect(annexB.sublist(0, 4), orderedEquals([0, 0, 0, 1]));

    final nals = splitH264AnnexB(annexB);
    expect(nals, isNotEmpty);
    final firstNalType = nals.first[0] & 0x1F;
    expect([7, 8, 5].contains(firstNalType), isTrue,
        reason: 'expected SPS/PPS/IDR NAL first, got $firstNalType');
  });

  test('forced keyframe mid-stream is honored', () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'h264',
      width: 160,
      height: 120,
      bitrate: 200000,
      framerate: 30,
    ));
    final src = FakeVideoSource(width: 160, height: 120, framerate: 30);
    const forceAt = 6;
    for (var i = 0; i < 12; i++) {
      encoder.encode(
        src.frameAt(1000 + i),
        VideoEncoderEncodeOptions(keyFrame: i == forceAt),
      );
    }
    await encoder.flush();
    encoder.close();

    expect(chunks.length, 12);
    expect(chunks[0].type, EncodedVideoChunkType.key);
    expect(chunks[forceAt].type, EncodedVideoChunkType.key);
  });

  test('output round-trips through the RTP packetizer/depacketizer',
      () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'h264',
      width: 160,
      height: 120,
      bitrate: 200000,
      framerate: 30,
    ));
    final src = FakeVideoSource(width: 160, height: 120, framerate: 30);
    for (var i = 0; i < 3; i++) {
      encoder.encode(src.frameAt(1000 + i));
    }
    await encoder.flush();
    encoder.close();

    final packetizer = H264Packetizer(maxPayloadSize: 300);
    final depacketizer = H264Depacketizer();
    for (final src in chunks) {
      final parts = packetizer.packetize(
        src.data,
        isKeyFrame: src.type == EncodedVideoChunkType.key,
      );
      EncodedVideoChunk? out;
      for (final (p, m) in parts) {
        final r =
            depacketizer.depacketize(p, marker: m, timestamp: src.timestamp);
        if (r != null) out = r;
      }
      expect(out, isNotNull);
      expect(out!.data, src.data);
      expect(out.type, src.type);
    }
  });
}
