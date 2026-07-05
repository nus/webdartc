/// H.264 video decoder backend powered by Cisco's OpenH264.
///
/// Mirrors [H264EncoderBackend]: registered alongside the encoder by
/// [registerH264Codec] on non-Apple platforms (macOS uses VideoToolbox).
///
/// The OpenH264 decoder doesn't track presentation timestamps through
/// its API — `SBufferInfo.uiInBsTimeStamp` is wall-clock-ish and set by
/// the decoder itself. We instead maintain a FIFO of input PTS values
/// and pop one on each successful output. This is correct for the WebRTC
/// H.264 profile (constrained baseline / no B-frames), where decode
/// order equals display order. It would *not* be correct for full
/// High profile bitstreams with B-frames.
library;

import 'dart:collection';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import '_openh264.dart' as wels;
import 'openh264/bindings.g.dart' as oh;

final class H264DecoderBackend implements VideoDecoderBackend {
  ffi.Pointer<oh.ISVCDecoder>? _decoder;
  void Function(VideoFrame)? _onOutput;
  void Function(Object)? _onError;

  // FIFO of (timestamp_us) values for frames pushed into DecodeFrameNoDelay.
  // OpenH264 emits output frames in input order for baseline-profile
  // bitstreams, so we pop from the front on each successful output.
  final Queue<int> _ptsQueue = Queue<int>();

  @override
  set onOutput(void Function(VideoFrame) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoDecoderConfig config) {
    if (_decoder != null) return;
    final ppDec = pkgffi.calloc<ffi.Pointer<oh.ISVCDecoder>>();
    final createRes = wels.welsCreateDecoder(ppDec);
    if (createRes != 0 || ppDec.value == ffi.nullptr) {
      pkgffi.calloc.free(ppDec);
      throw StateError('WelsCreateDecoder failed: $createRes');
    }
    final handle = ppDec.value;
    pkgffi.calloc.free(ppDec);
    final vtbl = handle.value.ref;

    final param = pkgffi.calloc<oh.SDecodingParam>();
    // Defaults are fine: real-time, no error-concealment, no LTR.
    final init = vtbl.Initialize.asFunction<
        int Function(
          ffi.Pointer<oh.ISVCDecoder>,
          ffi.Pointer<oh.SDecodingParam>,
        )>();
    final initRes = init(handle, param);
    pkgffi.calloc.free(param);
    if (initRes != 0) {
      wels.welsDestroyDecoder(handle);
      throw StateError('ISVCDecoder.Initialize failed: $initRes');
    }
    _decoder = handle;
  }

  @override
  void decode(EncodedVideoChunk chunk) {
    final decoder = _decoder;
    if (decoder == null) {
      _onError?.call(StateError('Decoder not configured'));
      return;
    }

    final src = pkgffi.calloc<ffi.UnsignedChar>(chunk.data.length);
    src
        .cast<ffi.Uint8>()
        .asTypedList(chunk.data.length)
        .setAll(0, chunk.data);
    final ppDst = pkgffi.calloc<ffi.Pointer<ffi.UnsignedChar>>(3);
    final info = pkgffi.calloc<oh.SBufferInfo>();

    final vtbl = decoder.value.ref;
    final decodeFn = vtbl.DecodeFrameNoDelay.asFunction<
        int Function(
          ffi.Pointer<oh.ISVCDecoder>,
          ffi.Pointer<ffi.UnsignedChar>,
          int,
          ffi.Pointer<ffi.Pointer<ffi.UnsignedChar>>,
          ffi.Pointer<oh.SBufferInfo>,
        )>();

    _ptsQueue.add(chunk.timestamp);
    try {
      final res = decodeFn(decoder, src, chunk.data.length, ppDst, info);
      if (res != 0) {
        // dsErrorFree (0) is success; any other value is a non-fatal
        // decoder warning (e.g. dsRefLost for a P-frame after packet
        // loss). Treat as a dropped frame, not a hard error — drop the
        // PTS we queued for this AU.
        if (_ptsQueue.isNotEmpty) _ptsQueue.removeFirst();
        return;
      }
      if (info.ref.iBufferStatus != 1) {
        // No frame ready yet (likely SPS/PPS-only AU). Don't pop the
        // PTS — the next AU that produces output will consume it in
        // input order.
        return;
      }
      final pts = _ptsQueue.isEmpty ? chunk.timestamp : _ptsQueue.removeFirst();
      _emitFrame(info.ref, ppDst, pts);
    } finally {
      pkgffi.calloc.free(info);
      pkgffi.calloc.free(ppDst);
      pkgffi.calloc.free(src);
    }
  }

  void _emitFrame(oh.SBufferInfo info,
      ffi.Pointer<ffi.Pointer<ffi.UnsignedChar>> ppDst, int pts) {
    final mem = info.UsrData.sSystemBuffer;
    final w = mem.iWidth;
    final h = mem.iHeight;
    final yStride = mem.iStride[0];
    final uvStride = mem.iStride[1];
    final uvW = (w + 1) >> 1;
    final uvH = (h + 1) >> 1;
    // OpenH264 always returns I420 (videoFormatI420 = 23).
    final out = Uint8List(w * h + 2 * uvW * uvH);
    var off = 0;
    _copyPlane(ppDst[0].cast<ffi.Uint8>(), yStride, out, off, w, h);
    off += w * h;
    _copyPlane(ppDst[1].cast<ffi.Uint8>(), uvStride, out, off, uvW, uvH);
    off += uvW * uvH;
    _copyPlane(ppDst[2].cast<ffi.Uint8>(), uvStride, out, off, uvW, uvH);

    _onOutput?.call(VideoFrame(
      data: out,
      codedWidth: w,
      codedHeight: h,
      format: VideoPixelFormat.i420,
      timestamp: pts,
    ));
  }

  static void _copyPlane(ffi.Pointer<ffi.Uint8> src, int srcStride,
      Uint8List dst, int dstOff, int w, int h) {
    if (srcStride == w) {
      dst.setRange(dstOff, dstOff + w * h, src.asTypedList(w * h));
      return;
    }
    for (var y = 0; y < h; y++) {
      dst.setRange(
          dstOff + y * w, dstOff + (y + 1) * w, (src + y * srcStride).asTypedList(w));
    }
  }

  @override
  Future<void> flush() async {
    final decoder = _decoder;
    if (decoder == null) return;
    final vtbl = decoder.value.ref;
    final ppDst = pkgffi.calloc<ffi.Pointer<ffi.UnsignedChar>>(3);
    final info = pkgffi.calloc<oh.SBufferInfo>();
    final flushFn = vtbl.FlushFrame.asFunction<
        int Function(
          ffi.Pointer<oh.ISVCDecoder>,
          ffi.Pointer<ffi.Pointer<ffi.UnsignedChar>>,
          ffi.Pointer<oh.SBufferInfo>,
        )>();
    try {
      // Loop because FlushFrame may return one buffered frame at a time.
      while (true) {
        final res = flushFn(decoder, ppDst, info);
        if (res != 0 || info.ref.iBufferStatus != 1) break;
        final pts =
            _ptsQueue.isEmpty ? 0 : _ptsQueue.removeFirst();
        _emitFrame(info.ref, ppDst, pts);
      }
    } finally {
      pkgffi.calloc.free(info);
      pkgffi.calloc.free(ppDst);
    }
  }

  @override
  void reset() => close();

  @override
  void close() {
    final decoder = _decoder;
    if (decoder != null) {
      final vtbl = decoder.value.ref;
      final uninit = vtbl.Uninitialize.asFunction<
          int Function(ffi.Pointer<oh.ISVCDecoder>)>();
      uninit(decoder);
      wels.welsDestroyDecoder(decoder);
      _decoder = null;
    }
    _ptsQueue.clear();
  }
}
