@Tags(['native'])
@TestOn('mac-os')
library;

import 'package:test/test.dart';
import 'package:webdartc/codec/codec_registry.dart';
import 'package:webdartc/codec/h264/videotoolbox_decoder_backend.dart';
import 'package:webdartc/codec/h264/videotoolbox_encoder_backend.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/media/video_frame.dart';

void main() {
  setUpAll(() {
    CodecRegistry.registerVideoEncoder('h264', VideoToolboxEncoderBackend.new);
    CodecRegistry.registerVideoDecoder('h264', VideoToolboxDecoderBackend.new);
  });

  test('encoder -> decoder round-trip preserves dimensions and pts', () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('enc: $e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'h264',
      width: 160,
      height: 120,
      bitrate: 200000,
      framerate: 30,
    ));
    final src = FakeVideoSource(width: 160, height: 120, framerate: 30);
    for (var i = 0; i < 8; i++) {
      encoder.encode(src.frameAt(1000 + i));
    }
    await encoder.flush();
    encoder.close();

    final decoded = <VideoFrame>[];
    final decoder = VideoDecoder(
      output: decoded.add,
      error: (e) => fail('dec: $e'),
    );
    decoder.configure(const VideoDecoderConfig(codec: 'h264'));
    for (final c in chunks) {
      decoder.decode(c);
    }
    await decoder.flush();
    decoder.close();

    expect(decoded, isNotEmpty);
    expect(decoded.length, chunks.length);
    for (final f in decoded) {
      expect(f.codedWidth, 160);
      expect(f.codedHeight, 120);
      expect(f.format, VideoPixelFormat.i420);
      expect(f.data.length, 160 * 120 * 3 ~/ 2);
    }
    final ptsIn = chunks.map((c) => c.timestamp).toList();
    final ptsOut = decoded.map((f) => f.timestamp).toList();
    expect(ptsOut, ptsIn);
  });

  test('decoder produces a plausible luma plane (non-trivial content)',
      () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('enc: $e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'h264',
      width: 160,
      height: 120,
      bitrate: 400000,
      framerate: 30,
    ));
    final src = FakeVideoSource(width: 160, height: 120, framerate: 30);
    encoder.encode(src.frameAt(1234));
    await encoder.flush();
    encoder.close();

    final decoded = <VideoFrame>[];
    final decoder = VideoDecoder(
      output: decoded.add,
      error: (e) => fail('dec: $e'),
    );
    decoder.configure(const VideoDecoderConfig(codec: 'h264'));
    decoder.decode(chunks.first);
    await decoder.flush();
    decoder.close();

    expect(decoded, hasLength(1));
    final luma = decoded.first.data.sublist(0, 160 * 120);
    final distinct = luma.toSet().length;
    // FakeVideoSource renders a ms-timestamp bitmap, so luma must span a
    // meaningful range — both black (text) and white (background).
    expect(distinct, greaterThan(1),
        reason: 'decoded luma is solid; decoder/encoder likely broken');
  });
}
