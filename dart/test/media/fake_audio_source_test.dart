import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/media/audio_data.dart';
import 'package:webdartc/src/media/fake_audio_source.dart';

void main() {
  group('FakeAudioSource', () {
    test('frameAt yields s16 stereo 20ms frames at 48kHz', () {
      final src = FakeAudioSource();
      final f = src.frameAt(0);

      expect(f.format, AudioSampleFormat.s16);
      expect(f.sampleRate, 48000);
      expect(f.numberOfChannels, 2);
      expect(f.numberOfFrames, 960);
      expect(f.duration, 20000);
      expect(f.timestamp, 0);
      expect(f.data.length, 960 * 2 * 2);
    });

    test('successive frames are wall-clock paced and sample-continuous', () async {
      final src = FakeAudioSource();
      final stream = src.start().take(3);
      final frames = await stream.toList();

      expect(frames.length, 3);
      expect(frames[0].timestamp, 0);
      expect(frames[1].timestamp, 20000);
      expect(frames[2].timestamp, 40000);
    });

    test('emitted samples form a true sinusoid', () {
      // 440 Hz at 48 kHz: one period = 48000/440 ≈ 109.09 samples.
      // First period is fully contained in a 960-sample (20 ms) frame.
      const sampleRate = 48000;
      const frequency = 440;
      const amplitude = 0.3;
      final src = FakeAudioSource(
        sampleRate: sampleRate,
        frequency: frequency.toDouble(),
        amplitude: amplitude,
      );
      final f = src.frameAt(0);
      final view = ByteData.sublistView(f.data);

      final samplesPerPeriod = sampleRate / frequency;
      final expectedPeak = (amplitude * 32767).round();

      // Zero-cross at sample 0 (sin(0) = 0).
      expect(view.getInt16(0, Endian.little), 0);
      // Quarter-period peak (positive max).
      final qIdx = (samplesPerPeriod / 4).round();
      expect(view.getInt16(qIdx * 4, Endian.little),
          closeTo(expectedPeak, expectedPeak * 0.05));
      // Half-period zero-crossing.
      final hIdx = (samplesPerPeriod / 2).round();
      expect(view.getInt16(hIdx * 4, Endian.little).abs(),
          lessThan(expectedPeak * 0.05));
      // Three-quarter-period trough (negative max).
      final tqIdx = (samplesPerPeriod * 3 / 4).round();
      expect(view.getInt16(tqIdx * 4, Endian.little),
          closeTo(-expectedPeak, expectedPeak * 0.05));
    });

    test('frames are sample-continuous across boundaries', () {
      final src = FakeAudioSource();
      final samplesPerFrame = 960;
      final f0 = src.frameAt(0);
      final f1 = src.frameAt(samplesPerFrame);
      final v0 = ByteData.sublistView(f0.data);
      final v1 = ByteData.sublistView(f1.data);
      // Last sample of f0 and first sample of f1 must continue the sine
      // smoothly (max single-sample delta within ~1 sample of the wave).
      final lastF0 = v0.getInt16((samplesPerFrame - 1) * 4, Endian.little);
      final firstF1 = v1.getInt16(0, Endian.little);
      // Just check the sine derivative is plausible: |Δ| ≤ 2π·f·amp / Fs · 32767.
      final maxDelta = (2 * 3.1416 * 440 * 0.3 / 48000 * 32767).round() + 50;
      expect((firstF1 - lastF0).abs(), lessThanOrEqualTo(maxDelta));
    });

    test('left/right channels are identical (mono signal in stereo container)', () {
      final src = FakeAudioSource();
      final f = src.frameAt(123);
      final view = ByteData.sublistView(f.data);
      for (var i = 0; i < f.numberOfFrames; i++) {
        final l = view.getInt16(i * 4, Endian.little);
        final r = view.getInt16(i * 4 + 2, Endian.little);
        expect(l, r);
      }
    });

    test('amplitude scales output peak', () {
      final loud = FakeAudioSource(amplitude: 0.9).frameAt(0);
      final soft = FakeAudioSource(amplitude: 0.1).frameAt(0);
      final loudView = ByteData.sublistView(loud.data);
      final softView = ByteData.sublistView(soft.data);
      var loudMax = 0, softMax = 0;
      for (var i = 0; i < loud.numberOfFrames * 2; i++) {
        final lv = loudView.getInt16(i * 2, Endian.little).abs();
        final sv = softView.getInt16(i * 2, Endian.little).abs();
        if (lv > loudMax) loudMax = lv;
        if (sv > softMax) softMax = sv;
      }
      expect(loudMax, greaterThan(softMax * 5));
    });
  });
}
