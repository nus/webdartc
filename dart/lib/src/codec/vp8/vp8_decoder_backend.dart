/// VP8 video decoder backend powered by libvpx.
///
/// Registered alongside the encoder by [registerVp8Codec]. The wrapper
/// shim (`webdartc_vp8.{h,c}`) hides every libvpx symbol and exposes a
/// drain-pattern decode API that this backend mirrors directly.
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import '_libvpx.dart' as vp8;

/// libvpx-backed VP8 decoder.
final class Vp8DecoderBackend implements VideoDecoderBackend {
  ffi.Pointer<vp8.WebdartcVp8Decoder>? _dec;

  void Function(VideoFrame)? _onOutput;
  void Function(Object)? _onError;

  // Growable persistent input scratch — RTP-assembled chunks range from
  // a few hundred bytes (delta) to 30+ KB (key), so size on demand with
  // a 1.5x policy and never shrink. Avoids one calloc/free per packet.
  ffi.Pointer<ffi.Uint8> _inScratch = ffi.nullptr;
  int _inScratchCap = 0;

  @override
  set onOutput(void Function(VideoFrame) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoDecoderConfig config) {
    final dec = vp8.vp8DecoderCreate();
    if (dec == ffi.nullptr) {
      throw StateError('webdartc_vp8_decoder_create failed');
    }
    _dec = dec;
    // Width / height come from the bitstream itself (VP8 keyframe header
    // §9.1), so any dimensions in `config` are ignored.
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
        vp8.vp8DecoderDecode(dec, _inScratch, data.length, chunk.timestamp);
    if (res != 0) {
      _onError?.call(StateError('webdartc_vp8_decoder_decode failed: $res'));
      return;
    }
    _drain();
  }

  void _drain() {
    final dec = _dec!;
    while (true) {
      final f = vp8.vp8DecoderDrainOne(dec);
      if (f == ffi.nullptr) break;
      try {
        final width = vp8.vp8FrameWidth(f);
        final height = vp8.vp8FrameHeight(f);
        final ptr = vp8.vp8FrameData(f);
        final size = width * height * 3 ~/ 2;
        final copy = Uint8List.fromList(ptr.asTypedList(size));
        _onOutput?.call(VideoFrame(
          format: VideoPixelFormat.i420,
          codedWidth: width,
          codedHeight: height,
          timestamp: vp8.vp8FramePtsUs(f),
          data: copy,
        ));
      } finally {
        vp8.vp8FrameFree(f);
      }
    }
  }

  @override
  Future<void> flush() async {
    // libvpx returns frames synchronously; nothing buffered.
  }

  @override
  void reset() => close();

  @override
  void close() {
    final dec = _dec;
    if (dec != null) {
      vp8.vp8DecoderDestroy(dec);
      _dec = null;
    }
    if (_inScratch != ffi.nullptr) {
      pkgffi.calloc.free(_inScratch);
      _inScratch = ffi.nullptr;
      _inScratchCap = 0;
    }
  }
}
