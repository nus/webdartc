/// VP9 video encoder backend powered by libvpx. Registered by
/// [registerVp9Codec] (in `vp9_codec.dart`). libvpx is statically linked
/// into `webdartc_vp9.dylib`; only the `webdartc_vp9_*` wrapper symbols
/// cross the FFI boundary.
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import '_libvpx9.dart' as vp9;

final class Vp9EncoderBackend implements VideoEncoderBackend {
  ffi.Pointer<vp9.WebdartcVp9Encoder>? _enc;
  VideoDecoderConfig? _decoderConfig;

  void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?)? _onOutput;
  void Function(Object)? _onError;

  int _width = 0;
  int _height = 0;

  // Persistent native I420 staging — see Vp8EncoderBackend for rationale.
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

    final enc = vp9.vp9EncoderCreate(
        _width, _height, bitrateKbps, fps * 4 /* keyframe ~4 s */);
    if (enc == ffi.nullptr) {
      throw StateError('webdartc_vp9_encoder_create failed');
    }
    _enc = enc;
    _inScratchSize = _width * _height * 3 ~/ 2;
    _inScratch = pkgffi.calloc<ffi.Uint8>(_inScratchSize);
    _decoderConfig = VideoDecoderConfig(
      codec: 'vp9',
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
      _onError?.call(StateError('VP9 encoder requires I420 input'));
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

    final res = vp9.vp9EncoderEncode(
        enc, yPtr, uPtr, vPtr, _width, _height,
        frame.timestamp, keyFrame ? 1 : 0);
    if (res != 0) {
      _onError?.call(StateError('webdartc_vp9_encoder_encode failed: $res'));
      return;
    }
    _drain(frame.timestamp);
  }

  void _drain(int timestamp) {
    final enc = _enc!;
    while (true) {
      final out = vp9.vp9EncoderDrainOne(enc);
      if (out == ffi.nullptr) break;
      try {
        final size = vp9.vp9OutputSize(out);
        final data =
            Uint8List.fromList(vp9.vp9OutputData(out).asTypedList(size));
        final isKey = vp9.vp9OutputIsKeyframe(out) != 0;
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
        vp9.vp9OutputFree(out);
      }
    }
  }

  @override
  Future<void> flush() async {}

  @override
  void reset() => close();

  @override
  void close() {
    final enc = _enc;
    if (enc != null) {
      vp9.vp9EncoderDestroy(enc);
      _enc = null;
    }
    if (_inScratch != ffi.nullptr) {
      pkgffi.calloc.free(_inScratch);
      _inScratch = ffi.nullptr;
      _inScratchSize = 0;
    }
  }
}
