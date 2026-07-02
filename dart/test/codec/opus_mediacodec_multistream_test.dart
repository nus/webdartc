/// Verifies that multiple MediaCodec Opus encoder + decoder instances run
/// simultaneously without cross-talk. Each pair owns its own `AMediaCodec`, so a
/// regression that shared state across instances (or leaked codec resources
/// across a close/reconfigure) would surface here as cross-stream PTS
/// interleaving or a failure to re-open. The audio analogue of
/// `vp8_mediacodec_multistream_test.dart` / `h264_mediacodec_multistream_test.dart`.
///
/// On Android `registerOpusCodec` selects the MediaCodec backends. MediaCodec is
/// Android-only, so this gates off host `dart test` and runs on-device via
/// flutter/example/integration_test/dart_suite_test.dart.
@Tags(['native'])
@TestOn('android')
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/audio_codec.dart';
import 'package:webdartc/codec/opus/opus_codec.dart';
import 'package:webdartc/media/audio_data.dart';

class _Stream {
  _Stream(this.id);

  final int id;
  static const int sampleRate = 48000;
  static const int channels = 2;
  static const int samplesPerFrame = 960; // 20 ms

  late final AudioEncoder encoder;
  late final AudioDecoder decoder;

  final chunks = <EncodedAudioChunk>[];
  final decoded = <AudioData>[];
  final encErrors = <Object>[];
  final decErrors = <Object>[];

  void open() {
    encoder = AudioEncoder(
      output: (c, _) => chunks.add(c),
      error: encErrors.add,
    );
    decoder = AudioDecoder(
      output: decoded.add,
      error: decErrors.add,
    );
    encoder.configure(const AudioEncoderConfig(
      codec: AudioCodecName.opus,
      sampleRate: sampleRate,
      numberOfChannels: channels,
      bitrate: 32000,
    ));
    decoder.configure(const AudioDecoderConfig(
      codec: AudioCodecName.opus,
      sampleRate: sampleRate,
      numberOfChannels: channels,
    ));
  }

  void step(int frameIndex) {
    final beforeChunks = chunks.length;
    encoder.encode(_sineFrame(frameIndex));
    for (var i = beforeChunks; i < chunks.length; i++) {
      decoder.decode(chunks[i]);
    }
  }

  // A 440 Hz sine, s16 interleaved stereo, timestamped in this stream's own
  // PTS space (`id`-prefixed) so cross-talk between streams is detectable.
  AudioData _sineFrame(int frameIndex) {
    final pcm = Int16List(samplesPerFrame * channels);
    final start = frameIndex * samplesPerFrame;
    for (var i = 0; i < samplesPerFrame; i++) {
      final v = (math.sin(2 * math.pi * 440 * (start + i) / sampleRate) * 12000)
          .round();
      pcm[i * channels] = v;
      pcm[i * channels + 1] = v;
    }
    return AudioData(
      format: AudioSampleFormat.s16,
      sampleRate: sampleRate,
      numberOfChannels: channels,
      numberOfFrames: samplesPerFrame,
      timestamp: 1000000 * id + frameIndex * 20000,
      data: pcm.buffer.asUint8List(),
    );
  }

  Future<void> close() async {
    await encoder.flush();
    encoder.close();
    await decoder.flush();
    decoder.close();
  }
}

void main() {
  setUpAll(registerOpusCodec);

  test('3 MediaCodec Opus encoder+decoder pairs interleaved, 30 frames each',
      () async {
    const numStreams = 3;
    const framesPerStream = 30;

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
      expect(s.chunks.length, greaterThanOrEqualTo(framesPerStream ~/ 2),
          reason: 'stream ${s.id}: most frames should encode');
      expect(s.decoded, isNotEmpty, reason: 'stream ${s.id}: decoded frames');
      // PTS must round-trip in order and belong to *this* stream (no cross-talk).
      final pts = s.decoded.map((d) => d.timestamp).toList();
      expect(pts, equals(List.of(pts)..sort()),
          reason: 'stream ${s.id}: pts monotonic');
      for (final t in pts) {
        expect(t ~/ 1000000, s.id,
            reason: 'stream ${s.id}: pts must originate from this stream');
      }
      for (final d in s.decoded) {
        expect(d.format, AudioSampleFormat.s16);
        expect(d.numberOfChannels, _Stream.channels);
        expect(d.sampleRate, _Stream.sampleRate);
      }
    }
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('3 MediaCodec Opus encoder+decoder pair lifecycles back-to-back',
      () async {
    for (var s = 0; s < 3; s++) {
      final stream = _Stream(s)..open();
      for (var f = 0; f < 12; f++) {
        stream.step(f);
      }
      await stream.close();
      expect(stream.encErrors, isEmpty, reason: 'iter $s: enc errors');
      expect(stream.decErrors, isEmpty, reason: 'iter $s: dec errors');
      expect(stream.decoded, isNotEmpty, reason: 'iter $s: decoded');
    }
  }, timeout: const Timeout(Duration(seconds: 90)));
}
