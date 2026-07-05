/// VP9 video decoder backend powered by libvpx.
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import '_libvpx9.dart' as vp9;

final class Vp9DecoderBackend implements VideoDecoderBackend {
  ffi.Pointer<vp9.WebdartcVp9Decoder>? _dec;

  void Function(VideoFrame)? _onOutput;
  void Function(Object)? _onError;

  // Growable persistent scratch — see Vp8DecoderBackend for rationale.
  ffi.Pointer<ffi.Uint8> _inScratch = ffi.nullptr;
  int _inScratchCap = 0;

  @override
  set onOutput(void Function(VideoFrame) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoDecoderConfig config) {
    final dec = vp9.vp9DecoderCreate();
    if (dec == ffi.nullptr) {
      throw StateError('webdartc_vp9_decoder_create failed');
    }
    _dec = dec;
  }

  @override
  void decode(EncodedVideoChunk chunk) {
    final dec = _dec;
    if (dec == null) {
      _onError?.call(StateError('Decoder not configured'));
      return;
    }
    final data = chunk.data;
    if (data.length > _inScratchCap) {
      if (_inScratch != ffi.nullptr) pkgffi.calloc.free(_inScratch);
      _inScratchCap = (data.length * 3) >> 1;
      _inScratch = pkgffi.calloc<ffi.Uint8>(_inScratchCap);
    }
    _inScratch.asTypedList(data.length).setAll(0, data);
    final res =
        vp9.vp9DecoderDecode(dec, _inScratch, data.length, chunk.timestamp);
    if (res != 0) {
      _onError?.call(StateError('webdartc_vp9_decoder_decode failed: $res'));
      return;
    }
    _drain();
  }

  void _drain() {
    final dec = _dec!;
    while (true) {
      final f = vp9.vp9DecoderDrainOne(dec);
      if (f == ffi.nullptr) break;
      try {
        final width = vp9.vp9FrameWidth(f);
        final height = vp9.vp9FrameHeight(f);
        final ptr = vp9.vp9FrameData(f);
        final size = width * height * 3 ~/ 2;
        final copy = Uint8List.fromList(ptr.asTypedList(size));
        _onOutput?.call(VideoFrame(
          format: VideoPixelFormat.i420,
          codedWidth: width,
          codedHeight: height,
          timestamp: vp9.vp9FramePtsUs(f),
          data: copy,
        ));
      } finally {
        vp9.vp9FrameFree(f);
      }
    }
  }

  @override
  Future<void> flush() async {}

  @override
  void reset() => close();

  @override
  void close() {
    final dec = _dec;
    if (dec != null) {
      vp9.vp9DecoderDestroy(dec);
      _dec = null;
    }
    if (_inScratch != ffi.nullptr) {
      pkgffi.calloc.free(_inScratch);
      _inScratch = ffi.nullptr;
      _inScratchCap = 0;
    }
  }
}
