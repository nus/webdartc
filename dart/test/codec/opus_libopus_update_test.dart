/// Regression tests sized for `dart/third_party/opus/` submodule bumps.
///
/// The existing `opus_test.dart` covers the typical 48 kHz/stereo/20 ms path
/// the rest of webdartc uses; this file adds enough config matrix and
/// quality-floor coverage that an automated libopus update (Renovate /
/// Dependabot bumping the submodule SHA) can rely on `dart test` to detect
/// regressions before the merge lands.
///
/// What this catches:
/// - Sample-rate sweep (8/12/16/24/48 kHz) — exercises libopus's NB/MB/WB/
///   SWB/FB internal modes; a regression in any of them shows up here.
/// - Mono vs stereo encoding paths.
/// - Quality regression at a fixed bitrate (SNR floor on a sine-wave input).
/// - Bitrate→size proportionality (catches mis-tuned rate-control).
/// - Bundled-libopus version drift (logs the version string + asserts shape).
///
/// Frame size is not parameterised here because [OpusEncoderBackend] hard-
/// codes 20 ms (WebRTC ptime default). If the backend grows a frame-size
/// configuration knob, extend this matrix to cover 5/10/40 ms too — those
/// hit different internal libopus paths (CELT-only vs SILK long-frame).
@Tags(['native'])
library;

import 'package:test/test.dart';
import 'package:webdartc/codec/audio_codec.dart';
import 'package:webdartc/codec/opus/opus_codec.dart';
import 'package:webdartc/media/audio_data.dart';

import 'opus_test_helpers.dart';

void main() {
  setUpAll(() {
    registerOpusCodec();
    // ignore: avoid_print
    print('libopus version: ${opusLibraryVersion()}');
  });

  test('libopus version string is well-formed', () {
    expect(opusLibraryVersion(), matches(RegExp(r'^libopus \S+')));
  });

  group('round-trip preserves a 440 Hz sine at SNR ≥ 15 dB', () {
    // Sample-rate sweep at stereo/20 ms. libopus accepts 8/12/16/24/48 kHz;
    // a regression in any internal mode (NB/MB/WB/SWB/FB) shows up here.
    for (final rate in const [8000, 12000, 16000, 24000, 48000]) {
      _expectRoundTripOk(sampleRate: rate, channels: 2, minSnrDb: 15.0);
    }

    // Mono path (the sweep above is all stereo).
    _expectRoundTripOk(sampleRate: 48000, channels: 1, minSnrDb: 15.0);
  });

  test('48 kHz stereo @ 96 kbps preserves sine at SNR ≥ 25 dB', () async {
    // Stricter quality floor than the matrix above. A libopus update that
    // silently downgrades mid-bitrate quality would breach this before the
    // 15 dB floor in the matrix.
    final snr = await _roundTripSnr(
      sampleRate: 48000, channels: 2, durationMs: 1000, bitrate: 96000,
    );
    expect(snr, greaterThan(25.0), reason: 'measured SNR=$snr dB');
  });

  test('higher bitrate produces proportionally larger encoded output',
      () async {
    final low = await _encodedBytes(bitrate: 16000);
    final high = await _encodedBytes(bitrate: 128000);
    // 128/16 = 8×; allow generous slack for VBR + payload overhead.
    final ratio = high / low;
    expect(ratio, greaterThan(4.0),
        reason: 'low=$low B, high=$high B (ratio=${ratio.toStringAsFixed(1)})');
    expect(ratio, lessThan(16.0),
        reason: 'low=$low B, high=$high B (ratio=${ratio.toStringAsFixed(1)})');
  });

  test('every chunk respects the RFC 6716 §3 1275-byte cap', () async {
    final input = sineFrame(
      sampleRate: 48000, channels: 2, frameCount: 48000 ~/ 5, // 200 ms
    );
    final chunks = await _encodeAudio(input,
        sampleRate: 48000, channels: 2, bitrate: 256000); // push hard
    for (final c in chunks) {
      expect(c.data.length, lessThanOrEqualTo(1275));
      expect(c.data.length, greaterThan(0));
    }
  });
}

void _expectRoundTripOk({
  required int sampleRate,
  required int channels,
  required double minSnrDb,
}) {
  test('${sampleRate}Hz × ${channels}ch', () async {
    final snr = await _roundTripSnr(
      sampleRate: sampleRate, channels: channels,
      durationMs: 200, bitrate: 64000,
    );
    expect(snr, greaterThan(minSnrDb), reason: 'measured SNR=$snr dB');
  });
}

Future<double> _roundTripSnr({
  required int sampleRate,
  required int channels,
  required int durationMs,
  required int bitrate,
}) async {
  final input = sineFrame(
    sampleRate: sampleRate, channels: channels,
    frameCount: sampleRate * durationMs ~/ 1000,
  );
  final chunks = await _encodeAudio(input,
      sampleRate: sampleRate, channels: channels, bitrate: bitrate);
  final decoded =
      await _decodeAll(chunks, sampleRate: sampleRate, channels: channels);
  return snrAfterAlignment(input.data, stitchAudio(decoded),
      sampleRate: sampleRate, channels: channels);
}

/// 200 ms of 48 kHz stereo sine encoded at [bitrate]; returns total byte size.
Future<int> _encodedBytes({required int bitrate}) async {
  final input = sineFrame(
    sampleRate: 48000, channels: 2, frameCount: 48000 ~/ 5, // 200 ms
  );
  final chunks = await _encodeAudio(input,
      sampleRate: 48000, channels: 2, bitrate: bitrate);
  return chunks.fold<int>(0, (a, c) => a + c.data.length);
}

Future<List<EncodedAudioChunk>> _encodeAudio(
  AudioData input, {
  required int sampleRate,
  required int channels,
  required int bitrate,
}) async {
  final chunks = <EncodedAudioChunk>[];
  final encoder = AudioEncoder(
    output: (c, _) => chunks.add(c),
    error: (e) => fail('encoder error: $e'),
  );
  encoder.configure(AudioEncoderConfig(
    codec: 'opus', sampleRate: sampleRate, numberOfChannels: channels,
    bitrate: bitrate,
  ));
  encoder.encode(input);
  await encoder.flush();
  encoder.close();
  return chunks;
}

Future<List<AudioData>> _decodeAll(
  List<EncodedAudioChunk> chunks, {
  required int sampleRate,
  required int channels,
}) async {
  final decoded = <AudioData>[];
  final decoder = AudioDecoder(
    output: decoded.add,
    error: (e) => fail('decoder error: $e'),
  );
  decoder.configure(AudioDecoderConfig(
    codec: 'opus', sampleRate: sampleRate, numberOfChannels: channels,
  ));
  for (final c in chunks) {
    decoder.decode(c);
  }
  await decoder.flush();
  decoder.close();
  return decoded;
}
