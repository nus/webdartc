/// H.264 video decoder backend powered by Apple VideoToolbox.
///
/// Available on macOS/iOS. The C helper (see `hook/build.dart`) owns the
/// VTDecompressionSession and emits I420 frames into a queue that this
/// backend drains synchronously.
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import 'videotoolbox/vt_helper.dart' as vt;

/// VideoToolbox-backed H.264 decoder.
final class VideoToolboxDecoderBackend implements VideoDecoderBackend {
  ffi.Pointer<vt.WvtDecoder>? _handle;

  void Function(VideoFrame)? _onOutput;
  void Function(Object)? _onError;

  @override
  set onOutput(void Function(VideoFrame) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoDecoderConfig config) {
    final handle = vt.wvtDecoderCreate();
    if (handle == ffi.nullptr) {
      throw StateError('VT decoder allocation failed');
    }
    _handle = handle;
    // VT decoder session is lazily initialized from SPS/PPS in the first
    // keyframe. Any `config.description` is ignored — we parse Annex B.
  }

  @override
  void decode(EncodedVideoChunk chunk) {
    final handle = _handle;
    if (handle == null) {
      _onError?.call(StateError('Decoder not configured'));
      return;
    }
    final data = chunk.data;
    final native = pkgffi.calloc<ffi.Uint8>(data.length);
    native.asTypedList(data.length).setAll(0, data);
    try {
      final res = vt.wvtDecoderDecode(
          handle, native, data.length, chunk.timestamp);
      if (res != 0) {
        _onError?.call(StateError('wvt_decoder_decode failed: $res'));
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
      final f = vt.wvtDecoderDrainOne(handle);
      if (f == ffi.nullptr) break;
      try {
        final width = vt.wvtDecodedFrameWidth(f);
        final height = vt.wvtDecodedFrameHeight(f);
        final size = vt.wvtDecodedFrameSize(f);
        final ptr = vt.wvtDecodedFrameData(f);
        final copy = Uint8List.fromList(ptr.asTypedList(size));
        _onOutput?.call(VideoFrame(
          format: VideoPixelFormat.i420,
          codedWidth: width,
          codedHeight: height,
          timestamp: vt.wvtDecodedFramePtsUs(f),
          data: copy,
        ));
      } finally {
        vt.wvtDecodedFrameFree(f);
      }
    }
  }

  @override
  Future<void> flush() async {
    // wvt_decoder_decode synchronously waits for async frames, so the
    // queue is drained by the time each decode call returns.
  }

  @override
  void reset() => close();

  @override
  void close() {
    final handle = _handle;
    if (handle != null) {
      vt.wvtDecoderDestroy(handle);
      _handle = null;
    }
  }
}
