@Tags(['native'])
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/h264/h264_encoder_backend.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/rtp/packetizer.dart';

void main() {
  setUpAll(registerH264Codec);

  test('H.264 encoder emits a keyframe on the first encoded frame '
      'and delta frames afterwards', () async {
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
    expect(chunks.first.data.length, greaterThan(0));
    // First bytes of a keyframe start with SPS (NAL type 7) after start code.
    final annexB = chunks.first.data;
    // Confirm the stream begins with an Annex B start code.
    expect(
      annexB.sublist(0, 4),
      anyOf(
        orderedEquals([0, 0, 0, 1]),
        // Some implementations may emit 3-byte start codes here.
        orderedEquals([0, 0, 1, 0]),
      ),
    );
    // The first NAL unit of a keyframe is usually SPS (type 7).
    final nals = splitH264AnnexB(annexB);
    expect(nals, isNotEmpty);
    final firstNalType = nals.first[0] & 0x1F;
    expect([7, 8, 5].contains(firstNalType), isTrue,
        reason: 'expected SPS/PPS/IDR, got NAL type $firstNalType');
  });

  test('H.264 forced keyframe mid-stream is honored', () async {
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

  test('H.264 output round-trips through the RTP packetizer/depacketizer',
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
        final r = depacketizer.depacketize(p, marker: m, timestamp: src.timestamp);
        if (r != null) out = r;
      }
      expect(out, isNotNull);
      expect(out!.data, src.data);
      expect(out.type, src.type);
    }
  });
}
