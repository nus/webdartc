/// H.264 video encoder backend powered by Android MediaCodec.
///
/// Available on Android. Wraps [MediaCodecH264Encoder] (a synchronous,
/// pure-Dart-FFI helper over the NDK `AMediaCodec`) and adapts it to the
/// generic W3C-style [VideoEncoderBackend]. Mirrors the VideoToolbox encoder
/// backend: I420 in, Annex B out, drained synchronously per `encode`.
library;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import 'mediacodec/mediacodec_helper.dart';

/// MediaCodec-backed H.264 encoder.
final class MediaCodecEncoderBackend implements VideoEncoderBackend {
  MediaCodecH264Encoder? _enc;
  VideoDecoderConfig? _decoderConfig;
  int _width = 0;
  int _height = 0;

  void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?)? _onOutput;
  void Function(Object)? _onError;

  @override
  set onOutput(
          void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?) cb) =>
      _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoEncoderConfig config) {
    _width = config.width;
    _height = config.height;
    final fps = (config.framerate ?? 30).round();
    final bitrate = config.bitrate ?? 400000;
    // Key frame every ~2 seconds. MediaCodec emits an IDR at start; periodic
    // IDRs come from this interval. (Per-frame force-IDR is not wired in v1.)
    const keyframeIntervalSec = 2;

    _enc = MediaCodecH264Encoder.create(
        _width, _height, bitrate, fps, keyframeIntervalSec);
    _decoderConfig = VideoDecoderConfig(
      codec: VideoCodecName.h264,
      codedWidth: _width,
      codedHeight: _height,
    );
  }

  @override
  void encode(VideoFrame frame, {bool keyFrame = false}) {
    final enc = _enc;
    if (enc == null) {
      _onError?.call(StateError('Encoder not configured'));
      return;
    }
    if (frame.format != VideoPixelFormat.i420) {
      _onError?.call(StateError('MediaCodec encoder requires I420 input'));
      return;
    }
    if (frame.codedWidth != _width || frame.codedHeight != _height) {
      _onError?.call(StateError(
          'Frame size mismatch: expected ${_width}x$_height, '
          'got ${frame.codedWidth}x${frame.codedHeight}'));
      return;
    }
    try {
      for (final unit in enc.encode(frame.data, frame.timestamp)) {
        _onOutput?.call(
          EncodedVideoChunk(
            type: unit.keyframe
                ? EncodedVideoChunkType.key
                : EncodedVideoChunkType.delta,
            timestamp: unit.ptsUs,
            data: unit.data,
          ),
          unit.keyframe
              ? EncodedVideoChunkMetadata(decoderConfig: _decoderConfig)
              : null,
        );
      }
    } catch (e) {
      _onError?.call(e);
    }
  }

  @override
  Future<void> flush() async {
    // encode() drains the codec synchronously, so nothing is buffered.
  }

  @override
  void reset() => close();

  @override
  void close() {
    _enc?.close();
    _enc = null;
  }
}
