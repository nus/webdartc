/// Android MediaCodec H.264 encoder/decoder helper (Android only).
///
/// Pure-Dart FFI over the NDK `libmediandk.so` (`AMediaCodec` / `AMediaFormat`),
/// driven entirely through the **synchronous** buffer API
/// (`dequeue`/`queueInputBuffer` + `dequeueOutputBuffer`). Because the
/// synchronous API delivers nothing on foreign threads, no C shim or
/// thread-safe queue is needed — unlike the macOS/iOS VideoToolbox helper,
/// which is callback-based and therefore needs `dart/src/wvt_callback.c`.
///
/// Each [MediaCodecH264Encoder] / [MediaCodecH264Decoder] owns one independent
/// `AMediaCodec` instance, so multiple streams just create multiple helpers;
/// all are driven on the calling isolate thread (see the codec registry / the
/// `*_multistream_test.dart` suites). The colour handling mirrors VideoToolbox:
/// frames are exchanged as packed I420 and converted to/from whatever planar
/// (`COLOR_FormatYUV420Planar` = 19) or semi-planar (`…SemiPlanar` = 21) layout
/// the codec uses, reading the codec's reported stride / slice-height.
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import 'bindings.g.dart';

// ── MediaCodec constants (stable Android values; safe to hardcode) ──────────
// These are android.media.MediaCodecInfo.CodecCapabilities / MediaCodec
// constants that the NDK does not export as symbols.

const int _colorFormatYUV420Planar = 19; // I420 (Y, U, V planes)
const int _colorFormatYUV420SemiPlanar = 21; // NV12 (Y, interleaved UV)
const int _colorFormatYUV420Flexible = 0x7F420888;

const int _configureFlagEncode = 1;
const int _bufferFlagCodecConfig = 2; // SPS/PPS config blob

// AMediaCodec_dequeueOutputBuffer sentinel indices.
const int _infoOutputFormatChanged = -2;
// -1 (TRY_AGAIN_LATER) / -3 (OUTPUT_BUFFERS_CHANGED) handled by `< 0` checks.
const int _infoTryAgainLater = -1;

const String _h264Mime = 'video/avc';

// H.264 Annex B NAL parsing.
const int _nalTypeMask = 0x1F;
const int _nalTypeIdr = 5;
const int _nalTypeSps = 7;

// Input/output dequeue timeouts (microseconds). Output drains non-blocking
// (0); input waits briefly so a momentarily-busy codec doesn't drop frames.
const int _inputTimeoutUs = 16000;
const int _outputTimeoutUs = 0;

// ── Library + bindings (loaded lazily on first use; Android only) ────────────

final MediaCodecBindings _mc =
    MediaCodecBindings(ffi.DynamicLibrary.open('libmediandk.so'));

bool _ok(media_status_t s) => s == media_status_t.AMEDIA_OK;

// ── Output value types ──────────────────────────────────────────────────────

/// One encoded H.264 access unit (Annex B byte-stream), SPS/PPS already
/// prepended on key frames.
final class EncodedH264 {
  final Uint8List data;
  final int ptsUs;
  final bool keyframe;
  const EncodedH264(this.data, this.ptsUs, this.keyframe);
}

/// One decoded frame as packed I420.
final class DecodedI420 {
  final Uint8List data;
  final int width;
  final int height;
  final int ptsUs;
  const DecodedI420(this.data, this.width, this.height, this.ptsUs);
}

// ── Colour conversion (pure Dart, unit-testable) ────────────────────────────

/// Packed I420 (`w*h` Y, then `w/2*h/2` U, then V) → packed NV12
/// (`w*h` Y, then interleaved `V`? no — U,V interleaved as U,V,U,V…).
///
/// Android's `COLOR_FormatYUV420SemiPlanar` is NV12: the chroma plane is
/// `U V U V …` (Cb first). I420 stores full U then full V planes, so we
/// interleave them.
Uint8List i420ToNv12(Uint8List i420, int w, int h) {
  final out = Uint8List(w * h + 2 * (w >> 1) * (h >> 1));
  i420ToNv12Into(i420, out, w, h);
  return out;
}

/// I420 → NV12 written directly into [dst] (must hold `w*h*3/2` bytes), so the
/// encoder can convert straight into the native MediaCodec input buffer with no
/// intermediate allocation on the per-frame hot path.
void i420ToNv12Into(Uint8List i420, Uint8List dst, int w, int h) {
  final ySize = w * h;
  final cw = w >> 1;
  final ch = h >> 1;
  dst.setRange(0, ySize, i420);
  final uOff = ySize;
  final vOff = ySize + cw * ch;
  var o = ySize;
  for (var i = 0; i < cw * ch; i++) {
    dst[o++] = i420[uOff + i];
    dst[o++] = i420[vOff + i];
  }
}

/// Strided planar YUV420 (`COLOR_FormatYUV420Planar`) → packed I420.
///
/// [stride] is the Y-plane row stride and [sliceHeight] the Y-plane height in
/// the source buffer; chroma planes use half of each (the common MediaCodec
/// convention).
Uint8List planarToI420(
    Uint8List src, int w, int h, int stride, int sliceHeight) {
  final out = Uint8List(w * h + 2 * (w >> 1) * (h >> 1));
  final cw = w >> 1;
  final cwStride = stride >> 1;
  final ySrc = 0;
  final uSrc = stride * sliceHeight;
  final vSrc = uSrc + cwStride * (sliceHeight >> 1);
  var o = 0;
  for (var r = 0; r < h; r++) {
    out.setRange(o, o + w, src, ySrc + r * stride);
    o += w;
  }
  for (var r = 0; r < (h >> 1); r++) {
    out.setRange(o, o + cw, src, uSrc + r * cwStride);
    o += cw;
  }
  for (var r = 0; r < (h >> 1); r++) {
    out.setRange(o, o + cw, src, vSrc + r * cwStride);
    o += cw;
  }
  return out;
}

/// Strided semi-planar NV12 (`COLOR_FormatYUV420SemiPlanar`) → packed I420.
Uint8List nv12ToI420(
    Uint8List src, int w, int h, int stride, int sliceHeight) {
  final out = Uint8List(w * h + 2 * (w >> 1) * (h >> 1));
  final cw = w >> 1;
  final chH = h >> 1;
  var o = 0;
  for (var r = 0; r < h; r++) {
    out.setRange(o, o + w, src, r * stride);
    o += w;
  }
  final uvBase = stride * sliceHeight;
  final uOff = w * h;
  final vOff = uOff + cw * chH;
  for (var r = 0; r < chH; r++) {
    final row = uvBase + r * stride;
    for (var c = 0; c < cw; c++) {
      out[uOff + r * cw + c] = src[row + 2 * c];
      out[vOff + r * cw + c] = src[row + 2 * c + 1];
    }
  }
  return out;
}

// ── Annex B helpers ─────────────────────────────────────────────────────────

/// Returns `(hasIdr, hasSps)` by scanning Annex B NAL unit types.
(bool, bool) _scanNals(Uint8List b) {
  var hasIdr = false, hasSps = false;
  final n = b.length;
  var i = 0;
  while (i + 3 < n) {
    // Match a 3- or 4-byte start code.
    if (b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1) {
      final t = b[i + 3] & _nalTypeMask;
      if (t == _nalTypeIdr) hasIdr = true;
      if (t == _nalTypeSps) hasSps = true;
      i += 4;
    } else if (i + 4 < n &&
        b[i] == 0 &&
        b[i + 1] == 0 &&
        b[i + 2] == 0 &&
        b[i + 3] == 1) {
      final t = b[i + 4] & _nalTypeMask;
      if (t == _nalTypeIdr) hasIdr = true;
      if (t == _nalTypeSps) hasSps = true;
      i += 5;
    } else {
      i++;
    }
  }
  return (hasIdr, hasSps);
}

// ── Small FFI scratch helpers ───────────────────────────────────────────────

ffi.Pointer<ffi.Char> _utf8(String s) => s.toNativeUtf8().cast<ffi.Char>();

// ── Encoder ─────────────────────────────────────────────────────────────────

final class MediaCodecH264Encoder {
  final ffi.Pointer<AMediaCodec> _codec;
  final int _width;
  final int _height;
  final int _inputColorFormat; // 19 (planar) or 21 (semi-planar)
  Uint8List? _csd; // SPS+PPS Annex B captured from the CODEC_CONFIG output

  // Reusable FFI scratch, allocated once and freed in close(), so the
  // per-frame hot path doesn't churn the C heap (mirrors the OpenH264 backend).
  final ffi.Pointer<ffi.Size> _sizePtr = pkgffi.calloc<ffi.Size>();
  final ffi.Pointer<AMediaCodecBufferInfo> _info =
      pkgffi.calloc<AMediaCodecBufferInfo>();

  MediaCodecH264Encoder._(
      this._codec, this._width, this._height, this._inputColorFormat);

  /// Creates and starts an H.264 encoder. Tries NV12 (best hardware
  /// compatibility) first, then planar I420 (no conversion; reliable on the
  /// emulator's software codec). Throws [StateError] if neither configures.
  static MediaCodecH264Encoder create(
      int width, int height, int bitrate, int fps, int keyframeIntervalSec) {
    Object? lastErr;
    for (final color in const [
      _colorFormatYUV420SemiPlanar,
      _colorFormatYUV420Planar,
    ]) {
      final mime = _utf8(_h264Mime);
      final codec = _mc.AMediaCodec_createEncoderByType(mime);
      pkgffi.malloc.free(mime);
      if (codec == ffi.nullptr) {
        lastErr = 'AMediaCodec_createEncoderByType returned null';
        continue;
      }
      final fmt = _buildEncoderFormat(
          width, height, bitrate, fps, keyframeIntervalSec, color);
      final cfg = _mc.AMediaCodec_configure(
          codec, fmt, ffi.nullptr, ffi.nullptr, _configureFlagEncode);
      _mc.AMediaFormat_delete(fmt);
      if (!_ok(cfg)) {
        lastErr = 'AMediaCodec_configure failed (color=$color): $cfg';
        _mc.AMediaCodec_delete(codec);
        continue;
      }
      if (!_ok(_mc.AMediaCodec_start(codec))) {
        lastErr = 'AMediaCodec_start failed (color=$color)';
        _mc.AMediaCodec_delete(codec);
        continue;
      }
      return MediaCodecH264Encoder._(codec, width, height, color);
    }
    throw StateError('MediaCodec H.264 encoder creation failed: $lastErr');
  }

  static ffi.Pointer<AMediaFormat> _buildEncoderFormat(int width, int height,
      int bitrate, int fps, int keyframeIntervalSec, int color) {
    final fmt = _mc.AMediaFormat_new();
    final mime = _utf8(_h264Mime);
    _mc.AMediaFormat_setString(fmt, _mc.AMEDIAFORMAT_KEY_MIME, mime);
    pkgffi.malloc.free(mime);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_WIDTH, width);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_HEIGHT, height);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_BIT_RATE, bitrate);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_FRAME_RATE, fps);
    _mc.AMediaFormat_setInt32(
        fmt, _mc.AMEDIAFORMAT_KEY_I_FRAME_INTERVAL, keyframeIntervalSec);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_COLOR_FORMAT, color);
    return fmt;
  }

  /// Encodes one packed-I420 frame and returns any encoded units now available
  /// (the synchronous codec may emit zero or more per call).
  List<EncodedH264> encode(Uint8List i420, int ptsUs) {
    final idx = _mc.AMediaCodec_dequeueInputBuffer(_codec, _inputTimeoutUs);
    if (idx < 0) return const []; // codec busy — skip this frame
    final frameSize = _width * _height * 3 ~/ 2;
    final buf = _mc.AMediaCodec_getInputBuffer(_codec, idx, _sizePtr);
    if (buf == ffi.nullptr || _sizePtr.value < frameSize) {
      // Can't fill the buffer; queue an empty one to release the slot.
      _mc.AMediaCodec_queueInputBuffer(_codec, idx, 0, 0, ptsUs, 0);
      return const [];
    }
    // Convert straight into the native input buffer — no intermediate copy.
    final dst = buf.asTypedList(frameSize);
    if (_inputColorFormat == _colorFormatYUV420SemiPlanar) {
      i420ToNv12Into(i420, dst, _width, _height);
    } else {
      dst.setAll(0, i420); // planar I420 needs no conversion
    }
    _mc.AMediaCodec_queueInputBuffer(_codec, idx, 0, frameSize, ptsUs, 0);
    return _drain();
  }

  List<EncodedH264> _drain() {
    final out = <EncodedH264>[];
    while (true) {
      final idx =
          _mc.AMediaCodec_dequeueOutputBuffer(_codec, _info, _outputTimeoutUs);
      if (idx == _infoTryAgainLater) break;
      if (idx < 0) continue; // FORMAT/BUFFERS changed — nothing to read
      final buf = _mc.AMediaCodec_getOutputBuffer(_codec, idx, _sizePtr);
      final off = _info.ref.offset;
      final len = _info.ref.size;
      final flags = _info.ref.flags;
      final pts = _info.ref.presentationTimeUs;
      if (buf != ffi.nullptr && len > 0) {
        final bytes = buf.asTypedList(off + len).sublist(off, off + len);
        if ((flags & _bufferFlagCodecConfig) != 0) {
          _csd = bytes; // SPS+PPS; emitted once, prepended to key frames
        } else {
          out.add(_finishUnit(bytes, pts));
        }
      }
      _mc.AMediaCodec_releaseOutputBuffer(_codec, idx, false);
    }
    return out;
  }

  EncodedH264 _finishUnit(Uint8List bytes, int ptsUs) {
    final (hasIdr, hasSps) = _scanNals(bytes);
    // MediaCodec emits SPS/PPS once via the CODEC_CONFIG buffer and does not
    // repeat them inline before each IDR; WebRTC peers need them with every
    // key frame, so prepend the cached config (mirrors the VideoToolbox path).
    if (hasIdr && !hasSps && _csd != null) {
      final csd = _csd!;
      final merged = Uint8List(csd.length + bytes.length)
        ..setRange(0, csd.length, csd)
        ..setRange(csd.length, csd.length + bytes.length, bytes);
      return EncodedH264(merged, ptsUs, true);
    }
    return EncodedH264(bytes, ptsUs, hasIdr);
  }

  void close() {
    _mc.AMediaCodec_stop(_codec);
    _mc.AMediaCodec_delete(_codec);
    pkgffi.calloc.free(_sizePtr);
    pkgffi.calloc.free(_info);
  }
}

// ── Decoder ─────────────────────────────────────────────────────────────────

final class MediaCodecH264Decoder {
  final ffi.Pointer<AMediaCodec> _codec;
  // Output layout, learned from INFO_OUTPUT_FORMAT_CHANGED before any frame.
  int _width;
  int _height;
  int _colorFormat = _colorFormatYUV420Planar;
  int _stride = 0;
  int _sliceHeight = 0;

  // Reusable FFI scratch (see the encoder), freed in close().
  final ffi.Pointer<ffi.Size> _sizePtr = pkgffi.calloc<ffi.Size>();
  final ffi.Pointer<AMediaCodecBufferInfo> _info =
      pkgffi.calloc<AMediaCodecBufferInfo>();
  final ffi.Pointer<ffi.Int32> _int32 = pkgffi.calloc<ffi.Int32>();

  MediaCodecH264Decoder._(this._codec, this._width, this._height);

  /// Creates and starts an H.264 decoder. SPS/PPS are not passed as csd —
  /// they arrive in-band on key frames (the encoder prepends them), which the
  /// decoder parses automatically.
  static MediaCodecH264Decoder create(int width, int height) {
    final mime = _utf8(_h264Mime);
    final codec = _mc.AMediaCodec_createDecoderByType(mime);
    pkgffi.malloc.free(mime);
    if (codec == ffi.nullptr) {
      throw StateError('AMediaCodec_createDecoderByType returned null');
    }
    final fmt = _mc.AMediaFormat_new();
    final m2 = _utf8(_h264Mime);
    _mc.AMediaFormat_setString(fmt, _mc.AMEDIAFORMAT_KEY_MIME, m2);
    pkgffi.malloc.free(m2);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_WIDTH, width);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_HEIGHT, height);
    final cfg =
        _mc.AMediaCodec_configure(codec, fmt, ffi.nullptr, ffi.nullptr, 0);
    _mc.AMediaFormat_delete(fmt);
    if (!_ok(cfg)) {
      _mc.AMediaCodec_delete(codec);
      throw StateError('AMediaCodec_configure (decoder) failed: $cfg');
    }
    if (!_ok(_mc.AMediaCodec_start(codec))) {
      _mc.AMediaCodec_delete(codec);
      throw StateError('AMediaCodec_start (decoder) failed');
    }
    return MediaCodecH264Decoder._(codec, width, height);
  }

  /// Decodes one Annex B access unit, returning any frames now available.
  List<DecodedI420> decode(Uint8List annexB, int ptsUs) {
    final idx = _mc.AMediaCodec_dequeueInputBuffer(_codec, _inputTimeoutUs);
    if (idx >= 0) {
      final buf = _mc.AMediaCodec_getInputBuffer(_codec, idx, _sizePtr);
      if (buf != ffi.nullptr && _sizePtr.value >= annexB.length) {
        buf.asTypedList(annexB.length).setAll(0, annexB);
        _mc.AMediaCodec_queueInputBuffer(
            _codec, idx, 0, annexB.length, ptsUs, 0);
      } else {
        _mc.AMediaCodec_queueInputBuffer(_codec, idx, 0, 0, ptsUs, 0);
      }
    }
    return _drain();
  }

  List<DecodedI420> _drain() {
    final out = <DecodedI420>[];
    while (true) {
      final idx =
          _mc.AMediaCodec_dequeueOutputBuffer(_codec, _info, _outputTimeoutUs);
      if (idx == _infoTryAgainLater) break;
      if (idx == _infoOutputFormatChanged) {
        _readOutputFormat();
        continue;
      }
      if (idx < 0) continue; // OUTPUT_BUFFERS_CHANGED — nothing to read
      final frame = _readFrame(idx, _info.ref);
      if (frame != null) out.add(frame);
      _mc.AMediaCodec_releaseOutputBuffer(_codec, idx, false);
    }
    return out;
  }

  void _readOutputFormat() {
    final fmt = _mc.AMediaCodec_getOutputFormat(_codec);
    if (fmt == ffi.nullptr) return;
    _width = _getInt(fmt, _mc.AMEDIAFORMAT_KEY_WIDTH, _width);
    _height = _getInt(fmt, _mc.AMEDIAFORMAT_KEY_HEIGHT, _height);
    _colorFormat =
        _getInt(fmt, _mc.AMEDIAFORMAT_KEY_COLOR_FORMAT, _colorFormat);
    _stride = _getInt(fmt, _mc.AMEDIAFORMAT_KEY_STRIDE, _width);
    _sliceHeight = _getInt(fmt, _mc.AMEDIAFORMAT_KEY_SLICE_HEIGHT, _height);
    _mc.AMediaFormat_delete(fmt);
  }

  DecodedI420? _readFrame(int idx, AMediaCodecBufferInfo info) {
    final len = info.size;
    if (len <= 0) return null;
    if (_stride == 0) _readOutputFormat(); // first frame before a format event
    final stride = _stride > 0 ? _stride : _width;
    final sliceHeight = _sliceHeight > 0 ? _sliceHeight : _height;
    final buf = _mc.AMediaCodec_getOutputBuffer(_codec, idx, _sizePtr);
    if (buf == ffi.nullptr) return null;
    final src = buf.asTypedList(info.offset + len);
    final view = info.offset == 0
        ? src
        : Uint8List.sublistView(src, info.offset);
    final Uint8List i420;
    switch (_colorFormat) {
      case _colorFormatYUV420Planar:
        i420 = planarToI420(view, _width, _height, stride, sliceHeight);
      case _colorFormatYUV420SemiPlanar:
        i420 = nv12ToI420(view, _width, _height, stride, sliceHeight);
      case _colorFormatYUV420Flexible:
        // Flexible has no fixed ByteBuffer layout; the decoder normally
        // reports a concrete 19/21 format instead. Skip frames we can't read.
        return null;
      default:
        return null; // vendor-proprietary tiled format — unsupported
    }
    return DecodedI420(i420, _width, _height, info.presentationTimeUs);
  }

  int _getInt(ffi.Pointer<AMediaFormat> fmt, ffi.Pointer<ffi.Char> key,
      int fallback) {
    final got = _mc.AMediaFormat_getInt32(fmt, key, _int32);
    return got ? _int32.value : fallback;
  }

  void close() {
    _mc.AMediaCodec_stop(_codec);
    _mc.AMediaCodec_delete(_codec);
    pkgffi.calloc.free(_sizePtr);
    pkgffi.calloc.free(_info);
    pkgffi.calloc.free(_int32);
  }
}
