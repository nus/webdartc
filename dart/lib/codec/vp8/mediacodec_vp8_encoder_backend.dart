/// VP8 video encoder backend powered by Android MediaCodec.
///
/// Available on Android when the device provides a VP8 encoder (probed at
/// registration; falls back to the bundled libvpx otherwise). Drives the
/// generic [MediaCodecVideoEncoder] with the `video/x-vnd.on2.vp8` MIME. VP8
/// has no out-of-band codec config (no SPS/PPS), so the [VideoUnitFinisher]
/// just reads MediaCodec's key-frame flag and passes the frame through
/// unchanged. I420 in, VP8 frames out, drained synchronously per `encode`.
library;

import 'dart:typed_data';

import '../../media/video_frame.dart';
import '../mediacodec/mediacodec_video.dart';
import '../mediacodec/mime_types.dart';
import '../video_codec.dart';

/// VP8 carries no out-of-band config; the key frame is marked by MediaCodec's
/// `BUFFER_FLAG_KEY_FRAME`, and the frame bytes are emitted as-is.
EncodedVideoUnit _vp8FinishUnit(
        Uint8List bytes, int flags, int ptsUs, Uint8List? csd) =>
    EncodedVideoUnit(bytes, ptsUs, (flags & bufferFlagKeyFrame) != 0);

/// MediaCodec-backed VP8 encoder.
final class MediaCodecVp8EncoderBackend implements VideoEncoderBackend {
  MediaCodecVideoEncoder? _enc;
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
    // Key frame every ~2 seconds (periodic IDRs from this interval; MediaCodec
    // also emits one at start). Per-frame force-keyframe is not wired in v1.
    const keyframeIntervalSec = 2;

    _enc = MediaCodecVideoEncoder.create(
      mime: vp8Mime,
      width: _width,
      height: _height,
      bitrate: bitrate,
      fps: fps,
      keyframeIntervalSec: keyframeIntervalSec,
      finishUnit: _vp8FinishUnit,
    );
    _decoderConfig = VideoDecoderConfig(
      codec: VideoCodecName.vp8,
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
