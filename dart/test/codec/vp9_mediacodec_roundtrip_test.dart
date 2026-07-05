/// MediaCodec VP9 encoder → decoder round-trip. Asserts that the first chunk is
/// a key frame (MediaCodec's `BUFFER_FLAG_KEY_FRAME`, surfaced by the shared
/// key-flag `finishUnit`), that dimensions/format/PTS round-trip, and that the
/// decoded image is non-trivial (catching a fully-broken encode/decode or
/// colour path). Unlike VP8 there is no 1-byte frame-tag key bit to
/// cross-check — the chunk type from the buffer flag is what the RTP layer
/// consumes.
///
/// Like VP8/H.264, VP9 has no out-of-band codec config, so there is no SPS/PPS
/// prepend to verify. Chroma is not asserted (FakeVideoSource renders neutral
/// chroma); the NV12<->I420 maths are covered host-side in
/// `mediacodec_color_test.dart`.
///
/// MediaCodec is Android-only, so this gates off host `dart test` and runs
/// on-device via flutter/example/integration_test/dart_suite_test.dart. The VP9
/// backend is MediaCodec-only on Android (SDP-gated by the availability
/// probe); on the API-35 emulator the software `c2.android.vp9.*` pair is
/// exercised.
@Tags(['native'])
@TestOn('android')
library;

import 'package:test/test.dart';
import 'package:webdartc/src/codec/video_codec.dart';
import 'package:webdartc/src/codec/vp9/vp9_codec.dart';
import 'package:webdartc/src/media/fake_video_source.dart';
import 'package:webdartc/src/media/video_frame.dart';

const int _width = 160;
const int _height = 120;

void main() {
  setUpAll(registerVp9Codec);

  test(
      'round-trip preserves dimensions/format/PTS, first chunk is a key frame, '
      'decoded luma is non-trivial', () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('enc: $e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: VideoCodecName.vp9,
      width: _width,
      height: _height,
      bitrate: 300000,
      framerate: 30,
    ));
    final src = FakeVideoSource(width: _width, height: _height, framerate: 30);
    const frames = 16;
    for (var i = 0; i < frames; i++) {
      encoder.encode(src.frameAt(1000 + i));
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, isNotEmpty);
    expect(chunks.first.type, EncodedVideoChunkType.key,
        reason: 'first encoded chunk must be a key frame');

    final decoded = <VideoFrame>[];
    final decoder = VideoDecoder(
      output: decoded.add,
      error: (e) => fail('dec: $e'),
    );
    decoder.configure(const VideoDecoderConfig(
      codec: VideoCodecName.vp9,
      codedWidth: _width,
      codedHeight: _height,
    ));
    for (final c in chunks) {
      decoder.decode(c);
    }
    await decoder.flush();
    decoder.close();

    // The sync codec keeps a few trailing frames in flight (no explicit EOS
    // flush), so don't require an exact 1:1 count — just the bulk, in order.
    expect(decoded, isNotEmpty);
    expect(decoded.length, greaterThanOrEqualTo(chunks.length ~/ 2));
    for (var i = 0; i < decoded.length; i++) {
      final f = decoded[i];
      expect(f.codedWidth, _width);
      expect(f.codedHeight, _height);
      expect(f.format, VideoPixelFormat.i420);
      expect(f.data.length, _width * _height * 3 ~/ 2);
      // VP9 (single layer, no reordering) round-trips PTS in input order.
      expect(f.timestamp, chunks[i].timestamp,
          reason: 'PTS must round-trip in input order');
    }

    // FakeVideoSource draws a timestamp bitmap into luma, so a correct
    // round-trip yields a range of luma values; a solid plane means the
    // encode/decode pipeline is broken.
    final luma = decoded.first.data.sublist(0, _width * _height);
    expect(luma.toSet().length, greaterThan(1), reason: 'decoded luma is solid');
  }, timeout: const Timeout(Duration(seconds: 60)));
}
