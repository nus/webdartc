/// Verifies that multiple `H264EncoderBackend` + `H264DecoderBackend`
/// instances can run simultaneously without cross-talk. Each pair owns
/// its own `ISVCEncoder` / `ISVCDecoder`, but a regression in our
/// wrapper (shared state, leaked vtables, the persistent
/// `_inScratch`/`_ppDst`/`_info` buffers introduced for hot-path perf)
/// would surface here as cross-stream PTS interleaving or frame
/// corruption.
///
/// macOS uses VideoToolbox so this test gates itself to Linux —
/// VT-side multistream coverage lives in
/// `videotoolbox_multistream_test.dart`.
@Tags(['native'])
@TestOn('linux')
library;

import 'package:test/test.dart';
import 'package:webdartc/codec/h264/h264_encoder_backend.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/media/video_frame.dart';

class _Stream {
  _Stream(this.id);

  final int id;
  static const int width = 160;
  static const int height = 120;
  static const double fps = 30;

  late final VideoEncoder encoder;
  late final VideoDecoder decoder;

  final chunks = <EncodedVideoChunk>[];
  final decoded = <VideoFrame>[];
  final encErrors = <Object>[];
  final decErrors = <Object>[];

  late final FakeVideoSource _src =
      FakeVideoSource(width: width, height: height, framerate: fps);

  void open() {
    encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: encErrors.add,
    );
    decoder = VideoDecoder(
      output: decoded.add,
      error: decErrors.add,
    );
    encoder.configure(VideoEncoderConfig(
      codec: 'h264',
      width: width,
      height: height,
      bitrate: 200000,
      framerate: fps,
    ));
    decoder.configure(VideoDecoderConfig(
      codec: 'h264',
      codedWidth: width,
      codedHeight: height,
    ));
  }

  void step(int frameIndex) {
    final beforeChunks = chunks.length;
    final raw = _src.frameAt(frameIndex);
    final pts = _ptsForFrame(frameIndex);
    encoder.encode(VideoFrame(
      format: raw.format,
      codedWidth: raw.codedWidth,
      codedHeight: raw.codedHeight,
      timestamp: pts,
      data: raw.data,
    ));
    for (var i = beforeChunks; i < chunks.length; i++) {
      decoder.decode(chunks[i]);
    }
  }

  int _ptsForFrame(int i) => 1000000 * id + i * 33333;

  Future<void> close() async {
    await encoder.flush();
    encoder.close();
    await decoder.flush();
    decoder.close();
  }
}

void main() {
  setUpAll(registerH264Codec);

  // Lower stream / frame count than the VP8/VP9 equivalents (4 × 30):
  // each ISVCEncoder spins up an internal worker thread pool, so on a
  // 2-vCPU Linux CI runner 4 concurrent encoder instances stretched the
  // wall-clock past the test framework's 60s timeout. 2 × 15 still
  // proves multi-instance isolation (the regression class this test
  // catches), without paying the full thread-pool cost.
  test('2 OpenH264 encoder+decoder pairs interleaved, 15 frames each',
      () async {
    const numStreams = 2;
    const framesPerStream = 15;

    final streams = [
      for (var i = 0; i < numStreams; i++) _Stream(i)..open(),
    ];

    for (var f = 0; f < framesPerStream; f++) {
      for (final s in streams) {
        s.step(f);
      }
    }

    for (final s in streams) {
      await s.close();
    }

    for (final s in streams) {
      expect(s.encErrors, isEmpty, reason: 'stream ${s.id}: enc errors');
      expect(s.decErrors, isEmpty, reason: 'stream ${s.id}: dec errors');
      expect(s.chunks, hasLength(framesPerStream),
          reason: 'stream ${s.id}: chunk count');
      expect(s.decoded, hasLength(framesPerStream),
          reason: 'stream ${s.id}: decoded count');
      final expectedPts = [
        for (var i = 0; i < framesPerStream; i++) s._ptsForFrame(i),
      ];
      expect(s.decoded.map((f) => f.timestamp).toList(), expectedPts,
          reason: 'stream ${s.id}: pts must round-trip in order');
      for (final fr in s.decoded) {
        expect(fr.codedWidth, _Stream.width);
        expect(fr.codedHeight, _Stream.height);
        expect(fr.format, VideoPixelFormat.i420);
      }
    }
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('3 OpenH264 encoder+decoder pair lifecycles back-to-back', () async {
    for (var s = 0; s < 3; s++) {
      final stream = _Stream(s)..open();
      for (var f = 0; f < 5; f++) {
        stream.step(f);
      }
      await stream.close();
      expect(stream.encErrors, isEmpty, reason: 'iter $s: enc errors');
      expect(stream.decErrors, isEmpty, reason: 'iter $s: dec errors');
      expect(stream.chunks, hasLength(5), reason: 'iter $s: chunks');
      expect(stream.decoded, hasLength(5), reason: 'iter $s: decoded');
    }
  }, timeout: const Timeout(Duration(seconds: 60)));
}
