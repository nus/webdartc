/// Generic video encoder backend powered by Android MediaCodec.
///
/// Available on Android when the device provides an encoder for the given
/// MIME (probed at registration). Drives the generic [MediaCodecVideoEncoder]
/// for codecs without out-of-band codec config — VP8 and VP9 carry no SPS/PPS,
/// so the [VideoUnitFinisher] just reads MediaCodec's key-frame flag and
/// passes the frame through unchanged. I420 in, compressed frames out,
/// drained synchronously per `encode`. H.264 keeps its own backend because it
/// must extract and prepend the CSD (SPS/PPS) on key frames.
library;

import 'dart:typed_data';

import '../../media/video_frame.dart';
import '../video_codec.dart';
import 'mediacodec_video.dart';

/// VP8/VP9 carry no out-of-band config; the key frame is marked by
/// MediaCodec's `BUFFER_FLAG_KEY_FRAME`, and the frame bytes are emitted
/// as-is.
EncodedVideoUnit _keyFlagFinishUnit(
        Uint8List bytes, int flags, int ptsUs, Uint8List? csd) =>
    EncodedVideoUnit(bytes, ptsUs, (flags & bufferFlagKeyFrame) != 0);

/// MediaCodec-backed video encoder, parameterised by MIME and the codec key
/// stamped into the emitted [VideoDecoderConfig].
final class MediaCodecVideoEncoderBackend implements VideoEncoderBackend {
  final String _mime;
  final String _codecName;
  MediaCodecVideoEncoder? _enc;
  VideoDecoderConfig? _decoderConfig;
  int _width = 0;
  int _height = 0;

  MediaCodecVideoEncoderBackend(this._mime, this._codecName);

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
      mime: _mime,
      width: _width,
      height: _height,
      bitrate: bitrate,
      fps: fps,
      keyframeIntervalSec: keyframeIntervalSec,
      finishUnit: _keyFlagFinishUnit,
    );
    _decoderConfig = VideoDecoderConfig(
      codec: _codecName,
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
