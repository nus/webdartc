@Tags(['native'])
@TestOn('mac-os')
library;

import 'package:test/test.dart';
import 'package:webdartc/src/codec/codec_registry.dart';
import 'package:webdartc/src/codec/h264/videotoolbox_decoder_backend.dart';
import 'package:webdartc/src/codec/h264/videotoolbox_encoder_backend.dart';
import 'package:webdartc/src/codec/video_codec.dart';
import 'package:webdartc/src/media/fake_video_source.dart';
import 'package:webdartc/src/media/video_frame.dart';

/// One encoder+decoder pair driven by [step]. Mirrors a single PeerConnection
/// stream that encodes its outbound frames and decodes inbound chunks.
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
      codec: VideoCodecName.h264,
      width: width,
      height: height,
      bitrate: 200000,
      framerate: fps,
    ));
    decoder.configure(const VideoDecoderConfig(codec: VideoCodecName.h264));
  }

  /// Encode one frame, drain new chunks into the decoder.
  void step(int frameIndex) {
    final beforeChunks = chunks.length;
    // FakeVideoSource.frameAt() always tags the frame with timestamp 0; we
    // rebuild the VideoFrame here with a real PTS so the round-trip can be
    // verified per-frame.
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

  int _ptsForFrame(int i) => 1000000 * id + i * 33333; // µs

  Future<void> close() async {
    await encoder.flush();
    encoder.close();
    await decoder.flush();
    decoder.close();
  }
}

void main() {
  setUpAll(() {
    CodecRegistry.registerVideoEncoder(VideoCodecName.h264, VideoToolboxEncoderBackend.new);
    CodecRegistry.registerVideoDecoder(VideoCodecName.h264, VideoToolboxDecoderBackend.new);
  });

  test('4 encoder+decoder pairs interleaved, 30 frames each', () async {
    const numStreams = 4;
    const framesPerStream = 30;

    final streams = [
      for (var i = 0; i < numStreams; i++) _Stream(i)..open(),
    ];

    // Round-robin one frame per stream per "tick" — the realistic SFU
    // client pattern that the Dart-only `isolateGroupBound` design crashed on.
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
          reason: 'stream ${s.id}: pts order');
      for (final fr in s.decoded) {
        expect(fr.codedWidth, _Stream.width);
        expect(fr.codedHeight, _Stream.height);
        expect(fr.format, VideoPixelFormat.i420);
      }
    }
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('5 encoder+decoder pair lifecycles back-to-back', () async {
    // Closing one pair and immediately opening another crashed Plan A's
    // isolateGroupBound design on the second iteration.
    for (var s = 0; s < 5; s++) {
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
