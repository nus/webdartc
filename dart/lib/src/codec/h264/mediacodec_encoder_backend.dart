/// H.264 video encoder backend powered by Android MediaCodec.
///
/// Available on Android. Drives the generic [MediaCodecVideoEncoder] (a
/// synchronous, pure-Dart-FFI helper over the NDK `AMediaCodec`) with the
/// `video/avc` MIME and an H.264-specific [VideoUnitFinisher] that re-attaches
/// the cached SPS/PPS to every key frame, and adapts it to the generic W3C-style
/// [VideoEncoderBackend]. Mirrors the VideoToolbox encoder backend: I420 in,
/// Annex B out, drained synchronously per `encode`.
library;

import 'dart:typed_data';

import '../../media/video_frame.dart';
import '../mediacodec/mediacodec_video.dart';
import '../mediacodec/mime_types.dart';
import '../video_codec.dart';
import 'nal_unit_types.dart';

/// Returns `(hasIdr, hasSps)` by scanning Annex B NAL unit types.
(bool, bool) _scanNals(Uint8List b) {
  var hasIdr = false, hasSps = false;
  final n = b.length;
  var i = 0;
  while (i + 3 < n) {
    // Match a 3- or 4-byte start code.
    if (b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1) {
      final t = b[i + 3] & H264NalType.mask;
      if (t == H264NalType.idr) hasIdr = true;
      if (t == H264NalType.sps) hasSps = true;
      i += 4;
    } else if (i + 4 < n &&
        b[i] == 0 &&
        b[i + 1] == 0 &&
        b[i + 2] == 0 &&
        b[i + 3] == 1) {
      final t = b[i + 4] & H264NalType.mask;
      if (t == H264NalType.idr) hasIdr = true;
      if (t == H264NalType.sps) hasSps = true;
      i += 5;
    } else {
      i++;
    }
  }
  return (hasIdr, hasSps);
}

/// MediaCodec emits SPS/PPS once via the CODEC_CONFIG buffer and does not repeat
/// them inline before each IDR; WebRTC peers need them with every key frame, so
/// prepend the cached config (mirrors the VideoToolbox path).
EncodedVideoUnit _h264FinishUnit(
    Uint8List bytes, int flags, int ptsUs, Uint8List? csd) {
  final (hasIdr, hasSps) = _scanNals(bytes);
  if (hasIdr && !hasSps && csd != null) {
    final merged = Uint8List(csd.length + bytes.length)
      ..setRange(0, csd.length, csd)
      ..setRange(csd.length, csd.length + bytes.length, bytes);
    return EncodedVideoUnit(merged, ptsUs, true);
  }
  return EncodedVideoUnit(bytes, ptsUs, hasIdr);
}

/// MediaCodec-backed H.264 encoder.
final class MediaCodecEncoderBackend implements VideoEncoderBackend {
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
    // Key frame every ~2 seconds. MediaCodec emits an IDR at start; periodic
    // IDRs come from this interval. (Per-frame force-IDR is not wired in v1.)
    const keyframeIntervalSec = 2;

    _enc = MediaCodecVideoEncoder.create(
      mime: h264Mime,
      width: _width,
      height: _height,
      bitrate: bitrate,
      fps: fps,
      keyframeIntervalSec: keyframeIntervalSec,
      finishUnit: _h264FinishUnit,
    );
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
