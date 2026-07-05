/// VP8 video encoder backend powered by libvpx. Registered by
/// [registerVp8Codec] (in `vp8_codec.dart`). libvpx itself is statically
/// linked into the bundled `webdartc_vp8.dylib`; only the
/// `webdartc_vp8_*` wrapper symbols are visible across the FFI boundary.
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import '_libvpx.dart' as vp8;
final class Vp8EncoderBackend implements VideoEncoderBackend {
  ffi.Pointer<vp8.WebdartcVp8Encoder>? _enc;
  VideoDecoderConfig? _decoderConfig;

  void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?)? _onOutput;
  void Function(Object)? _onError;

  int _width = 0;
  int _height = 0;

  // Persistent native I420 staging allocated in configure() and freed in
  // close() — avoids a calloc/free pair per frame on the encode path.
  ffi.Pointer<ffi.Uint8> _inScratch = ffi.nullptr;
  int _inScratchSize = 0;

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
    final bitrateKbps = ((config.bitrate ?? 400000) / 1000).round();

    final enc = vp8.vp8EncoderCreate(
        _width, _height, bitrateKbps, fps * 4 /* keyframe ~4 s */);
    if (enc == ffi.nullptr) {
      throw StateError('webdartc_vp8_encoder_create failed');
    }
    _enc = enc;
    _inScratchSize = _width * _height * 3 ~/ 2;
    _inScratch = pkgffi.calloc<ffi.Uint8>(_inScratchSize);
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
      _onError?.call(StateError('VP8 encoder requires I420 input'));
      return;
    }
    if (frame.codedWidth != _width || frame.codedHeight != _height) {
      _onError?.call(StateError(
          'Frame size mismatch: expected ${_width}x$_height, '
          'got ${frame.codedWidth}x${frame.codedHeight}'));
      return;
    }

    _inScratch.asTypedList(_inScratchSize).setAll(0, frame.data);
    final ySize = _width * _height;
    final uvSize = (_width >> 1) * (_height >> 1);
    final yPtr = _inScratch;
    final uPtr = _inScratch + ySize;
    final vPtr = _inScratch + (ySize + uvSize);

    final res = vp8.vp8EncoderEncode(
        enc, yPtr, uPtr, vPtr, _width, _height,
        frame.timestamp, keyFrame ? 1 : 0);
    if (res != 0) {
      _onError?.call(StateError('webdartc_vp8_encoder_encode failed: $res'));
      return;
    }
    _drain(frame.timestamp);
  }

  void _drain(int timestamp) {
    final enc = _enc!;
    while (true) {
      final out = vp8.vp8EncoderDrainOne(enc);
      if (out == ffi.nullptr) break;
      try {
        final size = vp8.vp8OutputSize(out);
        final data =
            Uint8List.fromList(vp8.vp8OutputData(out).asTypedList(size));
        final isKey = vp8.vp8OutputIsKeyframe(out) != 0;
        _onOutput?.call(
          EncodedVideoChunk(
            type: isKey
                ? EncodedVideoChunkType.key
                : EncodedVideoChunkType.delta,
            timestamp: timestamp,
            data: data,
          ),
          isKey
              ? EncodedVideoChunkMetadata(decoderConfig: _decoderConfig)
              : null,
        );
      } finally {
        vp8.vp8OutputFree(out);
      }
    }
  }

  @override
  Future<void> flush() async {
    final enc = _enc;
    if (enc == null) return;
    // Encode null-equivalent (zero-sized frame is not allowed; the flush
    // path used to pass a NULL image to vpx_codec_encode but the wrapper
    // doesn't expose that. With g_lag_in_frames left at the default 0
    // (which we don't override), libvpx in real-time mode emits each
    // frame synchronously so there's nothing to flush.)
  }

  @override
  void reset() => close();

  @override
  void close() {
    final enc = _enc;
    if (enc != null) {
      vp8.vp8EncoderDestroy(enc);
      _enc = null;
    }
    if (_inScratch != ffi.nullptr) {
      pkgffi.calloc.free(_inScratch);
      _inScratch = ffi.nullptr;
      _inScratchSize = 0;
    }
  }
}
