@Tags(['native'])
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/codec/vp8/vp8_encoder_backend.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/media/video_frame.dart';

void main() {
  setUpAll(registerVp8Codec);

  test('FakeVideoSource produces I420 frames with correct size', () async {
    final source = FakeVideoSource(width: 320, height: 240, framerate: 30);
    final stream = source.start().take(1);
    final frame = await stream.first;

    expect(frame.format, VideoPixelFormat.i420);
    expect(frame.codedWidth, 320);
    expect(frame.codedHeight, 240);
    expect(frame.data.length, 320 * 240 * 3 ~/ 2);
  });

  test('VP8 encoder emits a keyframe on the first encoded frame', () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(const VideoEncoderConfig(
      codec: 'vp8',
      width: 320,
      height: 240,
      bitrate: 400000,
      framerate: 30,
    ));

    final source = FakeVideoSource(width: 320, height: 240, framerate: 30);
    final frames = <VideoFrame>[];
    await for (final f in source.start().take(3)) {
      frames.add(f);
    }
    for (final f in frames) {
      encoder.encode(f);
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, isNotEmpty);
    expect(chunks.first.type, EncodedVideoChunkType.key);
    expect(chunks.first.data, isA<Uint8List>());
    expect(chunks.first.data.length, greaterThan(0));
  });
}
