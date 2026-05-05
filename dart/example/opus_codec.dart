/// Opus codec smoke test: encodes a generated sine wave through
/// [AudioEncoder]/[AudioDecoder] backed by libopus and reports stats.
///
/// Optionally writes the raw PCM input/output as headerless files you can
/// play with e.g.:
///   aplay -r 48000 -c 2 -f S16_LE /tmp/opus_in.pcm
///   aplay -r 48000 -c 2 -f S16_LE /tmp/opus_out.pcm
///
/// Usage:
///   dart run example/opus_codec.dart
///   dart run example/opus_codec.dart --write /tmp
///   dart run example/opus_codec.dart --duration 5 --bitrate 64000

import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:webdartc/webdartc.dart';

const int sampleRate = 48000;
const int channels = 2;
const int frameSamples = 960; // 20 ms

void main(List<String> args) async {
  final outDir = _flagValue(args, '--write');
  final durationSec = int.tryParse(_flagValue(args, '--duration') ?? '') ?? 2;
  final bitrate = int.tryParse(_flagValue(args, '--bitrate') ?? '') ?? 32000;

  registerOpusCodec();

  final totalSamplesPerChannel = sampleRate * durationSec;
  final inputPcm = _generateSineStereo(
    samplesPerChannel: totalSamplesPerChannel,
    freqHz: 440,
  );
  print('Input  : ${inputPcm.length} bytes '
      '(${durationSec}s @ ${sampleRate}Hz/${channels}ch s16)');

  final encoded = <EncodedAudioChunk>[];
  final encoder = AudioEncoder(
    output: (c, _) => encoded.add(c),
    error: (e) {
      print('Encoder error: $e');
      exit(1);
    },
  );
  encoder.configure(AudioEncoderConfig(
    codec: 'opus',
    sampleRate: sampleRate,
    numberOfChannels: channels,
    bitrate: bitrate,
  ));

  final encodeStart = DateTime.now();
  encoder.encode(AudioData(
    format: AudioSampleFormat.s16,
    sampleRate: sampleRate,
    numberOfChannels: channels,
    numberOfFrames: totalSamplesPerChannel,
    timestamp: 0,
    data: inputPcm,
  ));
  await encoder.flush();
  encoder.close();
  final encodeMs = DateTime.now().difference(encodeStart).inMicroseconds / 1000;

  final encodedTotal = encoded.fold<int>(0, (a, c) => a + c.data.length);
  final avgBytes = encoded.isEmpty ? 0 : (encodedTotal / encoded.length);
  final ratio = encodedTotal == 0 ? 0.0 : inputPcm.length / encodedTotal;
  print('Encoded: ${encoded.length} chunks, '
      '$encodedTotal bytes total, '
      '${avgBytes.toStringAsFixed(1)} bytes avg/chunk, '
      'compression ${ratio.toStringAsFixed(1)}× '
      '(in ${encodeMs.toStringAsFixed(1)} ms)');

  // Decode.
  final decoded = <AudioData>[];
  final decoder = AudioDecoder(
    output: decoded.add,
    error: (e) {
      print('Decoder error: $e');
      exit(1);
    },
  );
  decoder.configure(AudioDecoderConfig(
    codec: 'opus',
    sampleRate: sampleRate,
    numberOfChannels: channels,
  ));

  final decodeStart = DateTime.now();
  for (final c in encoded) {
    decoder.decode(c);
  }
  await decoder.flush();
  decoder.close();
  final decodeMs = DateTime.now().difference(decodeStart).inMicroseconds / 1000;

  final decodedSamples = decoded.fold<int>(0, (a, d) => a + d.numberOfFrames);
  print('Decoded: ${decoded.length} buffers, '
      '$decodedSamples samples/ch '
      '(${(decodedSamples / sampleRate).toStringAsFixed(2)}s) '
      'in ${decodeMs.toStringAsFixed(1)} ms');

  // Stitch decoded PCM, then phase-align via cross-correlation around the
  // encoder's algorithmic lookahead (Opus reports ~120 samples at 48 kHz)
  // before computing SNR.
  final outputPcm = _stitch(decoded);
  final inView = ByteData.sublistView(inputPcm);
  final outView = ByteData.sublistView(outputPcm);
  final inputRms = _rms(inView, inputPcm.length ~/ 2);
  final outputRms = _rms(outView, outputPcm.length ~/ 2);

  final delaySamples = _bestDelaySamples(inView, outView, channels);
  final snrDb = _snrAfterDelay(inView, outView, delaySamples, channels);
  print('Quality: input-RMS=${inputRms.toStringAsFixed(1)}, '
      'decoded-RMS=${outputRms.toStringAsFixed(1)}, '
      'codec delay=$delaySamples samples/ch, '
      'SNR≈${snrDb.toStringAsFixed(1)} dB '
      '(440 Hz sine, lossy)');

  if (outDir != null) {
    final inFile = File('$outDir/opus_in.pcm');
    final outFile = File('$outDir/opus_out.pcm');
    await inFile.writeAsBytes(inputPcm);
    await outFile.writeAsBytes(outputPcm);
    print('Wrote ${inFile.path} (${inputPcm.length} B), '
        '${outFile.path} (${outputPcm.length} B)');
    print('Play: aplay -r $sampleRate -c $channels -f S16_LE ${outFile.path}');
  }
}

Uint8List _generateSineStereo({
  required int samplesPerChannel,
  required double freqHz,
}) {
  final pcm = Uint8List(samplesPerChannel * channels * 2);
  final view = ByteData.sublistView(pcm);
  for (var i = 0; i < samplesPerChannel; i++) {
    final t = i / sampleRate;
    final s = (math.sin(2 * math.pi * freqHz * t) * 16384).round();
    for (var c = 0; c < channels; c++) {
      view.setInt16((i * channels + c) * 2, s, Endian.little);
    }
  }
  return pcm;
}

Uint8List _stitch(List<AudioData> buffers) {
  final total = buffers.fold<int>(0, (a, b) => a + b.data.length);
  final out = Uint8List(total);
  var offset = 0;
  for (final b in buffers) {
    out.setRange(offset, offset + b.data.length, b.data);
    offset += b.data.length;
  }
  return out;
}

double _rms(ByteData view, int sampleCount) {
  var sumSq = 0.0;
  for (var i = 0; i < sampleCount; i++) {
    final s = view.getInt16(i * 2, Endian.little);
    sumSq += s * s;
  }
  return math.sqrt(sumSq / sampleCount);
}

/// Search for the per-channel sample delay (0..480) that maximizes the
/// dot-product between input and output left channel — i.e. estimates the
/// codec's algorithmic delay so SNR isn't dominated by phase offset.
int _bestDelaySamples(ByteData inView, ByteData outView, int channels) {
  const maxDelay = 480; // 10 ms @ 48 kHz; Opus lookahead is ~120
  final inSamples = inView.lengthInBytes ~/ 2;
  final outSamples = outView.lengthInBytes ~/ 2;
  final compareLen = math.min(inSamples, outSamples) - maxDelay * channels;
  var bestDelay = 0;
  var bestDot = double.negativeInfinity;
  for (var d = 0; d <= maxDelay; d++) {
    var dot = 0.0;
    for (var i = 0; i < compareLen; i += channels) {
      final a = inView.getInt16(i * 2, Endian.little);
      final b = outView.getInt16((i + d * channels) * 2, Endian.little);
      dot += a * b;
    }
    if (dot > bestDot) {
      bestDot = dot;
      bestDelay = d;
    }
  }
  return bestDelay;
}

double _snrAfterDelay(
    ByteData inView, ByteData outView, int delaySamples, int channels) {
  final inSamples = inView.lengthInBytes ~/ 2;
  final outSamples = outView.lengthInBytes ~/ 2;
  final compareLen =
      math.min(inSamples, outSamples - delaySamples * channels);
  var signalSq = 0.0;
  var errorSq = 0.0;
  for (var i = 0; i < compareLen; i++) {
    final a = inView.getInt16(i * 2, Endian.little);
    final b = outView.getInt16((i + delaySamples * channels) * 2, Endian.little);
    signalSq += a * a;
    final e = a - b;
    errorSq += e * e;
  }
  if (errorSq == 0) return double.infinity;
  return 10 * math.log(signalSq / errorSq) / math.ln10;
}

String? _flagValue(List<String> args, String flag) {
  final idx = args.indexOf(flag);
  if (idx == -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
}
