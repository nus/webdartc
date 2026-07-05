/// MediaCodec Opus encoder → decoder round-trip through the registered
/// backends. Exercises the risky bit — the decoder's synthesised OpusHead / csd
/// — end to end: a sine wave is encoded to Opus and decoded back to PCM, and the
/// recovered signal is checked to be non-trivial (a correct csd ⇒ the decoder
/// actually produces audio; a wrong csd fails to configure or yields silence).
///
/// On Android `registerOpusCodec` selects the MediaCodec backends (this is where
/// they're exercised); the libopus round-trip is covered host-side in
/// `opus_test.dart`. MediaCodec is Android-only, so this gates off host
/// `dart test` and runs on-device via
/// flutter/example/integration_test/dart_suite_test.dart.
@Tags(['native'])
@TestOn('android')
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/codec/audio_codec.dart';
import 'package:webdartc/src/codec/opus/opus_codec.dart';
import 'package:webdartc/src/media/audio_data.dart';

const int _sampleRate = 48000;
const int _channels = 2;
const int _samplesPerFrame = 960; // 20 ms @ 48 kHz

/// One 20 ms frame of a 440 Hz sine, s16 interleaved stereo, phase-continuous
/// across [frameIndex].
AudioData _sineFrame(int frameIndex) {
  final pcm = Int16List(_samplesPerFrame * _channels);
  final startSample = frameIndex * _samplesPerFrame;
  for (var i = 0; i < _samplesPerFrame; i++) {
    final t = (startSample + i) / _sampleRate;
    final v = (math.sin(2 * math.pi * 440 * t) * 12000).round();
    pcm[i * _channels] = v;
    pcm[i * _channels + 1] = v;
  }
  return AudioData(
    format: AudioSampleFormat.s16,
    sampleRate: _sampleRate,
    numberOfChannels: _channels,
    numberOfFrames: _samplesPerFrame,
    timestamp: frameIndex * 20000,
    data: pcm.buffer.asUint8List(),
  );
}

double _rms(Uint8List pcmBytes) {
  final s = Int16List.view(pcmBytes.buffer, pcmBytes.offsetInBytes,
      pcmBytes.lengthInBytes ~/ 2);
  if (s.isEmpty) return 0;
  var sum = 0.0;
  for (final v in s) {
    sum += v * v;
  }
  return math.sqrt(sum / s.length);
}

void main() {
  setUpAll(registerOpusCodec);

  test('Opus encode → decode round-trips to a non-silent signal', () async {
    final chunks = <EncodedAudioChunk>[];
    final encoder = AudioEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('enc: $e'),
    );
    encoder.configure(const AudioEncoderConfig(
      codec: AudioCodecName.opus,
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
      bitrate: 32000,
    ));
    const frames = 25; // 0.5 s
    for (var f = 0; f < frames; f++) {
      encoder.encode(_sineFrame(f));
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, isNotEmpty, reason: 'encoder produced no Opus packets');
    for (final c in chunks) {
      expect(c.data.length, inInclusiveRange(1, 1275),
          reason: 'Opus packet size out of range');
    }

    final decoded = <AudioData>[];
    final decoder = AudioDecoder(
      output: decoded.add,
      error: (e) => fail('dec: $e'),
    );
    decoder.configure(const AudioDecoderConfig(
      codec: AudioCodecName.opus,
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
    ));
    for (final c in chunks) {
      decoder.decode(c);
    }
    await decoder.flush();
    decoder.close();

    expect(decoded, isNotEmpty, reason: 'decoder produced no PCM');
    for (final d in decoded) {
      expect(d.format, AudioSampleFormat.s16);
      expect(d.numberOfChannels, _channels);
      expect(d.sampleRate, _sampleRate);
    }
    // Opus discards the ~3840-sample (4-frame) pre-skip and the codec pipeline
    // holds a variable number of trailing frames — more when the (emulator) CPU
    // is busy. This guards against a broken pipeline that decodes almost
    // nothing, not an exact count, so require at least half the audio back.
    final totalFrames =
        decoded.fold<int>(0, (n, d) => n + d.numberOfFrames);
    expect(totalFrames, greaterThan(_samplesPerFrame * frames ~/ 2),
        reason: 'decoded far less audio than encoded');
    // A correct csd yields the sine back, not silence.
    final loudest = decoded.map((d) => _rms(d.data)).fold<double>(0, math.max);
    expect(loudest, greaterThan(1000),
        reason: 'decoded signal is silent — csd/OpusHead likely wrong');
  }, timeout: const Timeout(Duration(seconds: 60)));
}
