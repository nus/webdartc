/// VP9 encoder → decoder round-trip exercising the libvpx-bundled VP9
/// pair that `registerVp9Codec` wires up. Matches vp8_decoder_test —
/// the only thing that changes between VP8 and VP9 here is the codec
/// key threaded through `VideoEncoderConfig` / `VideoDecoderConfig`.
@Tags(['native'])
library;

import 'package:test/test.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/codec/vp9/vp9_codec.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/media/video_frame.dart';

void main() {
  setUpAll(registerVp9Codec);

  test('VP9 encoder emits a keyframe on the first frame and round-trips '
      'through the decoder preserving dimensions, format and PTS',
      () async {
    const width = 320, height = 240, frames = 5;

    final encoded = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => encoded.add(c),
      error: (e) => fail('encoder: $e'),
    );
    encoder.configure(const VideoEncoderConfig(
      codec: 'vp9',
      width: width,
      height: height,
      bitrate: 400000,
      framerate: 30,
    ));

    final src = FakeVideoSource(width: width, height: height, framerate: 30);
    for (var i = 0; i < frames; i++) {
      encoder.encode(src.frameAt(i * 33333));
    }
    await encoder.flush();
    encoder.close();
    expect(encoded, hasLength(frames));
    expect(encoded.first.type, EncodedVideoChunkType.key);

    final decoded = <VideoFrame>[];
    final decoder = VideoDecoder(
      output: decoded.add,
      error: (e) => fail('decoder: $e'),
    );
    decoder.configure(const VideoDecoderConfig(
      codec: 'vp9',
      codedWidth: width,
      codedHeight: height,
    ));
    for (final chunk in encoded) {
      decoder.decode(chunk);
    }
    await decoder.flush();
    decoder.close();

    expect(decoded, hasLength(frames));
    for (var i = 0; i < frames; i++) {
      expect(decoded[i].codedWidth, width);
      expect(decoded[i].codedHeight, height);
      expect(decoded[i].format, VideoPixelFormat.i420);
      expect(decoded[i].data.length, width * height * 3 ~/ 2,
          reason: 'I420 is 1.5 bytes per pixel — frame $i is malformed');
      expect(decoded[i].timestamp, encoded[i].timestamp,
          reason: 'PTS must round-trip from encode through decode');
    }
  });
}
