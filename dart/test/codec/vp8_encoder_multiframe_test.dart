@Tags(['native'])
@TestOn('!mac-os')
library;

import 'package:test/test.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/codec/vp8/vp8_encoder_backend.dart';
import 'package:webdartc/media/fake_video_source.dart';

void main() {
  setUpAll(registerVp8Codec);

  test('first frame is always a keyframe; subsequent are delta', () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'vp8',
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

    expect(chunks, hasLength(10));
    expect(chunks[0].type, EncodedVideoChunkType.key);
    for (var i = 1; i < chunks.length; i++) {
      expect(chunks[i].type, EncodedVideoChunkType.delta,
          reason: 'frame $i should be delta');
    }
  });

  test('forced keyframe via VideoEncoderEncodeOptions is honored mid-stream',
      () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'vp8',
      width: 160,
      height: 120,
      bitrate: 200000,
      framerate: 30,
    ));
    final src = FakeVideoSource(width: 160, height: 120, framerate: 30);
    const forceAt = 7;
    for (var i = 0; i < 15; i++) {
      encoder.encode(
        src.frameAt(1000 + i),
        VideoEncoderEncodeOptions(keyFrame: i == forceAt),
      );
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, hasLength(15));
    expect(chunks[0].type, EncodedVideoChunkType.key);
    for (var i = 1; i < chunks.length; i++) {
      final isKey = chunks[i].type == EncodedVideoChunkType.key;
      if (i == forceAt) {
        expect(isKey, isTrue, reason: 'forced keyframe at frame $i missing');
      } else {
        expect(isKey, isFalse, reason: 'unexpected keyframe at frame $i');
      }
    }
  });

  test('close() then reconfigure() allows re-encoding', () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'vp8',
      width: 160,
      height: 120,
      bitrate: 200000,
      framerate: 30,
    ));
    final src = FakeVideoSource(width: 160, height: 120);
    encoder.encode(src.frameAt(0));
    await encoder.flush();
    encoder.reset();

    encoder.configure(VideoEncoderConfig(
      codec: 'vp8',
      width: 320,
      height: 240,
      bitrate: 400000,
      framerate: 30,
    ));
    final src2 = FakeVideoSource(width: 320, height: 240);
    encoder.encode(src2.frameAt(0));
    await encoder.flush();
    encoder.close();

    expect(chunks, hasLength(2));
    expect(chunks[0].type, EncodedVideoChunkType.key);
    expect(chunks[1].type, EncodedVideoChunkType.key);
  });

  test('encoding a frame with mismatched dimensions reports an error', () {
    Object? captured;
    final encoder = VideoEncoder(
      output: (_, __) {},
      error: (e) => captured = e,
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'vp8',
      width: 160,
      height: 120,
      bitrate: 200000,
      framerate: 30,
    ));
    final wrongSize = FakeVideoSource(width: 320, height: 240);
    encoder.encode(wrongSize.frameAt(0));
    encoder.close();
    expect(captured, isA<StateError>());
  });
}
