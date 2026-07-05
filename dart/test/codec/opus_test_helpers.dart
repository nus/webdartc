/// Shared helpers for Opus codec tests: sine generation, PCM stitching,
/// and SNR measurement after codec-delay alignment.
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:webdartc/src/media/audio_data.dart';

/// Generates an [AudioData] holding a sine wave at [freqHz] (default 440 Hz),
/// signed 16-bit PCM, interleaved across [channels].
AudioData sineFrame({
  required int sampleRate,
  required int channels,
  required int frameCount,
  int timestampUs = 0,
  double freqHz = 440.0,
}) {
  final pcm = Uint8List(frameCount * channels * 2);
  final view = ByteData.sublistView(pcm);
  for (var i = 0; i < frameCount; i++) {
    final s = (math.sin(2 * math.pi * freqHz * i / sampleRate) * 16384).round();
    for (var c = 0; c < channels; c++) {
      view.setInt16((i * channels + c) * 2, s, Endian.little);
    }
  }
  return AudioData(
    format: AudioSampleFormat.s16,
    sampleRate: sampleRate,
    numberOfChannels: channels,
    numberOfFrames: frameCount,
    timestamp: timestampUs,
    data: pcm,
  );
}

/// Concatenates the PCM payloads of [buffers] into a single byte buffer.
Uint8List stitchAudio(List<AudioData> buffers) {
  final total = buffers.fold<int>(0, (a, b) => a + b.data.length);
  final out = Uint8List(total);
  var off = 0;
  for (final b in buffers) {
    out.setRange(off, off + b.data.length, b.data);
    off += b.data.length;
  }
  return out;
}

/// Computes signal-to-noise ratio (dB) between [inBytes] and [outBytes]
/// after correlating to find the codec's algorithmic delay.
///
/// Without alignment, even a perfect round-trip looks like noise because
/// Opus reports lookahead samples. The delay search caps at 10 ms scaled
/// to [sampleRate] — Opus lookahead is ~2.5 ms (120 samples @ 48 kHz), so
/// 10 ms gives plenty of margin without paying for the full input length.
double snrAfterAlignment(
  Uint8List inBytes,
  Uint8List outBytes, {
  required int sampleRate,
  required int channels,
}) {
  final inView = ByteData.sublistView(inBytes);
  final outView = ByteData.sublistView(outBytes);
  final maxDelay = sampleRate ~/ 100; // 10 ms in samples-per-channel
  final delay = _bestDelay(inView, outView, channels, maxDelay);
  final inSamples = inBytes.length ~/ 2;
  final outSamples = outBytes.length ~/ 2;
  final compareLen = math.min(inSamples, outSamples - delay * channels);
  if (compareLen <= 0) return double.negativeInfinity;
  var signalSq = 0.0;
  var errorSq = 0.0;
  for (var i = 0; i < compareLen; i++) {
    final a = inView.getInt16(i * 2, Endian.little);
    final b = outView.getInt16((i + delay * channels) * 2, Endian.little);
    signalSq += a * a;
    final e = a - b;
    errorSq += e * e;
  }
  if (errorSq == 0) return double.infinity;
  return 10 * math.log(signalSq / errorSq) / math.ln10;
}

int _bestDelay(
    ByteData inView, ByteData outView, int channels, int maxDelay) {
  final inSamples = inView.lengthInBytes ~/ 2;
  final outSamples = outView.lengthInBytes ~/ 2;
  final compareLen =
      math.min(inSamples, outSamples) - maxDelay * channels;
  if (compareLen <= 0) return 0;
  var bestDot = double.negativeInfinity;
  var bestDelay = 0;
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
