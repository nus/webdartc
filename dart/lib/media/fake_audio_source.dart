/// Fake audio source emitting a continuous sine-wave tone as 20 ms PCM
/// frames. Pure Dart — no microphone or platform plugin required. Useful
/// for media pipeline tests and sample apps.
library;

import 'dart:async';
import 'dart:math' as math;
import 'dart:typed_data';

import 'audio_data.dart';

/// Emits stereo s16 PCM frames carrying a constant tone at [frequency].
final class FakeAudioSource {
  final int sampleRate;
  final int numberOfChannels;
  final double frequency;
  final double amplitude;
  final int frameDurationUs;

  FakeAudioSource({
    this.sampleRate = 48000,
    this.numberOfChannels = 2,
    this.frequency = 440,
    this.amplitude = 0.3,
    this.frameDurationUs = 20000,
  })  : assert(sampleRate > 0),
        assert(numberOfChannels >= 1 && numberOfChannels <= 8),
        assert(frequency > 0),
        assert(amplitude > 0 && amplitude <= 1.0),
        assert(frameDurationUs > 0);

  /// Emits one frame every [frameDurationUs] until the subscription is
  /// cancelled. Wall-clock paced so a downstream encoder produces real-time
  /// output.
  Stream<AudioData> start() async* {
    final samplesPerFrame = (sampleRate * frameDurationUs) ~/ 1000000;
    final startUs = DateTime.now().microsecondsSinceEpoch;
    var nextTickUs = startUs;
    var sampleIndex = 0;
    while (true) {
      final timestampUs = (sampleIndex * 1000000) ~/ sampleRate;
      yield _frame(samplesPerFrame, sampleIndex, timestampUs);
      sampleIndex += samplesPerFrame;
      nextTickUs += frameDurationUs;
      final waitUs = nextTickUs - DateTime.now().microsecondsSinceEpoch;
      if (waitUs > 0) {
        await Future<void>.delayed(Duration(microseconds: waitUs));
      }
    }
  }

  /// Deterministic single-frame helper. Generates the frame whose first
  /// sample is at index [startIndex], without consulting the wall clock.
  AudioData frameAt(int startIndex) {
    final samplesPerFrame = (sampleRate * frameDurationUs) ~/ 1000000;
    final timestampUs = (startIndex * 1000000) ~/ sampleRate;
    return _frame(samplesPerFrame, startIndex, timestampUs);
  }

  AudioData _frame(int samplesPerFrame, int startIndex, int timestampUs) {
    final data = Uint8List(samplesPerFrame * numberOfChannels * 2);
    final view = ByteData.sublistView(data);
    final twoPiFOverFs = 2 * math.pi * frequency / sampleRate;
    final scale = (amplitude * 32767).round();
    for (var i = 0; i < samplesPerFrame; i++) {
      final v = (math.sin(twoPiFOverFs * (startIndex + i)) * scale).round();
      for (var ch = 0; ch < numberOfChannels; ch++) {
        view.setInt16((i * numberOfChannels + ch) * 2, v, Endian.little);
      }
    }
    return AudioData(
      format: AudioSampleFormat.s16,
      sampleRate: sampleRate,
      numberOfChannels: numberOfChannels,
      numberOfFrames: samplesPerFrame,
      timestamp: timestampUs,
      duration: frameDurationUs,
      data: data,
    );
  }
}
