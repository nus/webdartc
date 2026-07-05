/// W3C AudioData — raw audio sample data.
/// https://www.w3.org/TR/webcodecs/#audiodata-interface
library;

import 'dart:typed_data';

/// Sample formats for raw audio data.
enum AudioSampleFormat { u8, s16, s32, f32 }

/// A buffer of raw audio samples.
final class AudioData {
  final AudioSampleFormat format;
  final int sampleRate;
  final int numberOfChannels;
  final int numberOfFrames;

  /// Presentation timestamp in microseconds.
  final int timestamp;

  /// Duration in microseconds (optional).
  final int? duration;

  /// Raw sample data (interleaved channels).
  final Uint8List data;

  const AudioData({
    required this.format,
    required this.sampleRate,
    required this.numberOfChannels,
    required this.numberOfFrames,
    required this.timestamp,
    this.duration,
    required this.data,
  });

  /// Silence with the same shape as [src] — identical format, rate, layout
  /// and timestamp with zeroed samples. What a disabled audio track emits
  /// in place of its frames (W3C: silence, not gaps) so downstream
  /// packetizers/playout keep their cadence.
  factory AudioData.silenceLike(AudioData src) => AudioData(
        format: src.format,
        sampleRate: src.sampleRate,
        numberOfChannels: src.numberOfChannels,
        numberOfFrames: src.numberOfFrames,
        timestamp: src.timestamp,
        data: Uint8List(src.data.length),
      );

  /// Copy sample data to a new buffer.
  Uint8List copyTo() => Uint8List.fromList(data);

  /// Release resources associated with this data.
  void close() {}
}
