/// Verifies that multiple MediaCodec VP8 encoder + decoder instances run
/// simultaneously without cross-talk. Each pair owns its own `AMediaCodec`, so a
/// regression that shared state across instances (or leaked codec resources
/// across a close/reconfigure) would surface here as cross-stream PTS
/// interleaving, frame corruption, or a failure to re-open.
///
/// The libvpx VP8 multistream test (`vp8_multistream_test.dart`) covers the
/// bundled encoder used off-Android; this is the MediaCodec analogue and runs
/// where `registerVp8Codec` selects MediaCodec (Android).
///
/// MediaCodec only exists on Android, so this gates itself off host `dart test`
/// (no `libmediandk.so` there). It runs ON-DEVICE through the Flutter
/// integration aggregator (`flutter/example/integration_test/dart_suite_test.dart`),
/// which calls this file's `main()` directly under an Android emulator/device.
@Tags(['native'])
@TestOn('android')
library;

import 'package:test/test.dart';
import 'package:webdartc/src/codec/video_codec.dart';
import 'package:webdartc/src/codec/vp8/vp8_codec.dart';
import 'package:webdartc/src/media/fake_video_source.dart';
import 'package:webdartc/src/media/video_frame.dart';

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
      codec: VideoCodecName.vp8,
      width: width,
      height: height,
      bitrate: 200000,
      framerate: fps,
    ));
    decoder.configure(VideoDecoderConfig(
      codec: VideoCodecName.vp8,
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
  setUpAll(registerVp8Codec);

  test('3 MediaCodec VP8 encoder+decoder pairs interleaved, 20 frames each',
      () async {
    const numStreams = 3;
    const framesPerStream = 20;

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
      // The codec has pipeline latency, so a few trailing frames may stay
      // in flight — require the bulk to round-trip rather than an exact count.
      expect(s.chunks.length, greaterThanOrEqualTo(framesPerStream ~/ 2),
          reason: 'stream ${s.id}: most frames should encode');
      expect(s.decoded, isNotEmpty, reason: 'stream ${s.id}: decoded frames');
      // PTS must round-trip in order and belong to *this* stream (no cross-talk).
      final pts = s.decoded.map((f) => f.timestamp).toList();
      expect(pts, equals(List.of(pts)..sort()),
          reason: 'stream ${s.id}: pts monotonic');
      for (final t in pts) {
        expect(t ~/ 1000000, s.id,
            reason: 'stream ${s.id}: pts must originate from this stream');
      }
      for (final fr in s.decoded) {
        expect(fr.codedWidth, _Stream.width);
        expect(fr.codedHeight, _Stream.height);
        expect(fr.format, VideoPixelFormat.i420);
      }
    }
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('3 MediaCodec VP8 encoder+decoder pair lifecycles back-to-back',
      () async {
    for (var s = 0; s < 3; s++) {
      final stream = _Stream(s)..open();
      for (var f = 0; f < 8; f++) {
        stream.step(f);
      }
      await stream.close();
      expect(stream.encErrors, isEmpty, reason: 'iter $s: enc errors');
      expect(stream.decErrors, isEmpty, reason: 'iter $s: dec errors');
      expect(stream.decoded, isNotEmpty, reason: 'iter $s: decoded');
    }
  }, timeout: const Timeout(Duration(seconds: 90)));
}
