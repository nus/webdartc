/// MediaCodec H.264 encoder → decoder round-trip, covering what the multistream
/// test does not: that the first chunk is a key frame, that key frames carry an
/// in-band SPS (the MediaCodec-specific `_finishUnit` prepend of the codec's
/// CODEC_CONFIG blob — needed for WebRTC peers and untested elsewhere), and that
/// the decoded image is non-trivial (catching a fully-broken encode/decode or
/// colour path that a dimensions-only check would miss).
///
/// Chroma correctness is NOT asserted here on purpose: FakeVideoSource renders
/// neutral chroma (U=V=128), so the codec pipeline can't exercise it. The
/// NV12<->I420 interleave maths are covered with real U!=V data in the host
/// unit test `h264_mediacodec_color_test.dart`.
///
/// MediaCodec is Android-only, so this gates off host `dart test` and runs
/// on-device via flutter/example/integration_test/dart_suite_test.dart.
@Tags(['native'])
@TestOn('android')
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/h264/h264_encoder_backend.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/media/video_frame.dart';

const int _width = 160;
const int _height = 120;

/// True if [annexB] contains a NAL unit of [nalType] (5 = IDR, 7 = SPS),
/// scanning 3- and 4-byte start codes.
bool _hasNal(Uint8List b, int nalType) {
  for (var i = 0; i + 3 < b.length; i++) {
    if (b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1) {
      if ((b[i + 3] & 0x1F) == nalType) return true;
    } else if (i + 4 < b.length &&
        b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 0 && b[i + 3] == 1) {
      if ((b[i + 4] & 0x1F) == nalType) return true;
    }
  }
  return false;
}

void main() {
  setUpAll(registerH264Codec);

  test(
      'round-trip preserves dimensions/format/PTS, key frame carries SPS, '
      'decoded luma is non-trivial', () async {
    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('enc: $e'),
    );
    encoder.configure(VideoEncoderConfig(
      codec: VideoCodecName.h264,
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
    // MediaCodec emits SPS/PPS once via CODEC_CONFIG; `_finishUnit` must prepend
    // it so each key frame is self-contained (SPS=7 + IDR=5 present in-band).
    expect(_hasNal(chunks.first.data, 7), isTrue, reason: 'key frame missing SPS');
    expect(_hasNal(chunks.first.data, 5), isTrue, reason: 'key frame missing IDR');

    final decoded = <VideoFrame>[];
    final decoder = VideoDecoder(
      output: decoded.add,
      error: (e) => fail('dec: $e'),
    );
    decoder.configure(const VideoDecoderConfig(
      codec: VideoCodecName.h264,
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
      // Decode order == display order for baseline H.264, so PTS round-trips
      // in order.
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
