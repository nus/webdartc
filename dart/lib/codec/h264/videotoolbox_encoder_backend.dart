/// H.264 video encoder backend powered by Apple VideoToolbox.
///
/// Available on macOS/iOS. The underlying C helper (compiled via
/// `hook/build.dart`) owns the VTCompressionSession, handles the cross-thread
/// output callback, and produces Annex B bitstream.
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import 'videotoolbox/vt_helper.dart' as vt;

/// VideoToolbox-backed H.264 encoder.
final class VideoToolboxEncoderBackend implements VideoEncoderBackend {
  ffi.Pointer<vt.WvtEncoder>? _handle;
  VideoDecoderConfig? _decoderConfig;
  int _width = 0;
  int _height = 0;

  void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?)? _onOutput;
  void Function(Object)? _onError;

  @override
  set onOutput(void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?) cb) =>
      _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoEncoderConfig config) {
    _width = config.width;
    _height = config.height;
    final fps = (config.framerate ?? 30).round();
    final bitrate = config.bitrate ?? 400000;
    // Keyframe every ~2 seconds by default; callers can force IDR per-frame.
    const keyframeInterval = 60;

    final handle = vt.wvtEncoderCreate(
        _width, _height, bitrate, fps, keyframeInterval);
    if (handle == ffi.nullptr) {
      throw StateError('VTCompressionSession creation failed');
    }
    _handle = handle;
    _decoderConfig = VideoDecoderConfig(
      codec: 'h264',
      codedWidth: _width,
      codedHeight: _height,
    );
  }

  @override
  void encode(VideoFrame frame, {bool keyFrame = false}) {
    final handle = _handle;
    if (handle == null) {
      _onError?.call(StateError('Encoder not configured'));
      return;
    }
    if (frame.format != VideoPixelFormat.i420) {
      _onError?.call(StateError('VideoToolbox encoder requires I420 input'));
      return;
    }
    if (frame.codedWidth != _width || frame.codedHeight != _height) {
      _onError?.call(StateError(
          'Frame size mismatch: expected ${_width}x$_height, '
          'got ${frame.codedWidth}x${frame.codedHeight}'));
      return;
    }

    final total = frame.data.length;
    final native = pkgffi.calloc<ffi.Uint8>(total);
    native.asTypedList(total).setAll(0, frame.data);
    final yPtr = native;
    final ySize = _width * _height;
    final uvStride = _width >> 1;
    final uvSize = uvStride * (_height >> 1);
    final uPtr = native + ySize;
    final vPtr = native + (ySize + uvSize);

    try {
      final res = vt.wvtEncoderEncode(
          handle, yPtr, uPtr, vPtr, _width, uvStride,
          frame.timestamp, keyFrame ? 1 : 0);
      if (res != 0) {
        _onError?.call(StateError('wvt_encoder_encode failed: $res'));
        return;
      }
      _drain();
    } finally {
      pkgffi.calloc.free(native);
    }
  }

  void _drain() {
    final handle = _handle;
    if (handle == null) return;
    while (true) {
      final out = vt.wvtEncoderDrainOne(handle);
      if (out == ffi.nullptr) break;
      try {
        final size = vt.wvtEncoderOutputSize(out);
        final dataPtr = vt.wvtEncoderOutputData(out);
        final data = Uint8List.fromList(dataPtr.asTypedList(size));
        final pts = vt.wvtEncoderOutputPtsUs(out);
        final isKey = vt.wvtEncoderOutputIsKeyframe(out) != 0;
        _onOutput?.call(
          EncodedVideoChunk(
            type: isKey
                ? EncodedVideoChunkType.key
                : EncodedVideoChunkType.delta,
            timestamp: pts,
            data: data,
          ),
          isKey
              ? EncodedVideoChunkMetadata(decoderConfig: _decoderConfig)
              : null,
        );
      } finally {
        vt.wvtEncoderOutputFree(out);
      }
    }
  }

  @override
  Future<void> flush() async {
    // wvt_encoder_encode synchronously completes frames, so the queue is
    // always drained by the end of each encode call.
  }

  @override
  void reset() => close();

  @override
  void close() {
    final handle = _handle;
    if (handle != null) {
      vt.wvtEncoderDestroy(handle);
      _handle = null;
    }
  }
}
