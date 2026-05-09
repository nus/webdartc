@Tags(['native'])
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/audio_codec.dart';
import 'package:webdartc/codec/opus/opus_codec.dart';
import 'package:webdartc/media/audio_data.dart';

import 'opus_test_helpers.dart';

const _sampleRate = 48000;
const _channels = 2;
const _samplesPerFrame = 960; // 20ms at 48kHz

AudioData _sineFrame({required int frameCount, required int timestampUs}) {
  return sineFrame(
    sampleRate: _sampleRate,
    channels: _channels,
    frameCount: frameCount,
    timestampUs: timestampUs,
  );
}

void main() {
  setUpAll(registerOpusCodec);

  test('Opus encoder emits one chunk per 20 ms frame', () async {
    final chunks = <EncodedAudioChunk>[];
    final encoder = AudioEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(const AudioEncoderConfig(
      codec: 'opus',
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
      bitrate: 32000,
    ));

    // Feed 5 frames of 20 ms each.
    for (var i = 0; i < 5; i++) {
      encoder.encode(_sineFrame(
        frameCount: _samplesPerFrame,
        timestampUs: i * 20000,
      ));
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, hasLength(5));
    for (final c in chunks) {
      expect(c.type, EncodedAudioChunkType.key);
      expect(c.duration, 20000);
      expect(c.data.length, greaterThan(0));
      expect(c.data.length, lessThanOrEqualTo(1275)); // RFC 6716 §3
    }
    expect(chunks[0].timestamp, 0);
    expect(chunks[1].timestamp, 20000);
    expect(chunks[4].timestamp, 80000);
  });

  test('Opus encoder buffers sub-frame input and flushes when full', () async {
    final chunks = <EncodedAudioChunk>[];
    final encoder = AudioEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(const AudioEncoderConfig(
      codec: 'opus',
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
    ));

    // Two 480-sample buffers should produce exactly one 960-sample frame.
    encoder.encode(_sineFrame(frameCount: 480, timestampUs: 0));
    expect(chunks, isEmpty);
    encoder.encode(_sineFrame(frameCount: 480, timestampUs: 10000));
    expect(chunks, hasLength(1));
    expect(chunks[0].timestamp, 0);

    encoder.close();
  });

  test('Opus encode → decode round-trip recovers a similar signal', () async {
    final chunks = <EncodedAudioChunk>[];
    final encoder = AudioEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('$e'),
    );
    encoder.configure(const AudioEncoderConfig(
      codec: 'opus',
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
      bitrate: 64000,
    ));

    final input = _sineFrame(frameCount: _samplesPerFrame * 5, timestampUs: 0);
    encoder.encode(input);
    await encoder.flush();
    encoder.close();
    expect(chunks, hasLength(5));

    final decoded = <AudioData>[];
    final decoder = AudioDecoder(
      output: decoded.add,
      error: (e) => fail('$e'),
    );
    decoder.configure(const AudioDecoderConfig(
      codec: 'opus',
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
    ));
    for (final c in chunks) {
      decoder.decode(c);
    }
    await decoder.flush();
    decoder.close();

    expect(decoded, hasLength(5));
    for (final d in decoded) {
      expect(d.format, AudioSampleFormat.s16);
      expect(d.sampleRate, _sampleRate);
      expect(d.numberOfChannels, _channels);
      expect(d.numberOfFrames, _samplesPerFrame);
    }
    // Sanity: decoded output isn't all zeroes.
    final lastView = ByteData.sublistView(decoded.last.data);
    var maxAbs = 0;
    for (var i = 0; i < decoded.last.data.length; i += 2) {
      final s = lastView.getInt16(i, Endian.little);
      if (s.abs() > maxAbs) maxAbs = s.abs();
    }
    expect(maxAbs, greaterThan(1000));
  });

  test('Opus encoder rejects non-s16 input', () async {
    final errors = <Object>[];
    final encoder = AudioEncoder(
      output: (_, __) => fail('unexpected output'),
      error: errors.add,
    );
    encoder.configure(const AudioEncoderConfig(
      codec: 'opus',
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
    ));
    encoder.encode(AudioData(
      format: AudioSampleFormat.f32,
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
      numberOfFrames: _samplesPerFrame,
      timestamp: 0,
      data: Uint8List(_samplesPerFrame * _channels * 4),
    ));
    encoder.close();
    expect(errors, isNotEmpty);
  });
}
