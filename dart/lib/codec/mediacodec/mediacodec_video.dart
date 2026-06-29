/// Generic Android MediaCodec video encoder/decoder helper (Android only).
///
/// Pure-Dart FFI over the NDK `libmediandk.so` (`AMediaCodec` / `AMediaFormat`),
/// driven through the **synchronous** buffer API (`dequeue`/`queueInputBuffer`
/// + `dequeueOutputBuffer`). Because the synchronous API delivers nothing on
/// foreign threads, no C shim or thread-safe queue is needed — unlike the
/// macOS/iOS VideoToolbox helper, which is callback-based and therefore needs
/// `dart/src/wvt_callback.c`.
///
/// Codec-agnostic: the MIME string selects the codec (`video/avc` for H.264,
/// `video/x-vnd.on2.vp8` for VP8, …). The encoder is parameterised by a
/// [VideoUnitFinisher] that turns each raw output buffer into an
/// [EncodedVideoUnit] — this is where codec-specific output handling lives
/// (H.264 prepends the cached SPS/PPS to key frames; VP8 just reads the
/// key-frame flag). The decoder is fully shared (compressed frames in, packed
/// I420 out).
///
/// Each encoder/decoder owns one independent `AMediaCodec` instance, so
/// multiple streams just create multiple helpers; all are driven on the calling
/// isolate thread. Colour handling mirrors VideoToolbox: frames are exchanged as
/// packed I420 and converted to/from whatever planar
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
const int _bufferFlagCodecConfig = 2; // codec config blob (e.g. H.264 SPS/PPS)

/// `MediaCodec.BUFFER_FLAG_KEY_FRAME` — set on encoded key-frame output buffers.
/// Codecs without an out-of-band config (VP8/VP9) use this to mark key frames.
const int bufferFlagKeyFrame = 1;

// AMediaCodec_dequeueOutputBuffer sentinel indices.
const int _infoOutputFormatChanged = -2;
// -1 (TRY_AGAIN_LATER) / -3 (OUTPUT_BUFFERS_CHANGED) handled by `< 0` checks.
const int _infoTryAgainLater = -1;

// Input/output dequeue timeouts (microseconds). Output drains non-blocking
// (0); input waits briefly so a momentarily-busy codec doesn't drop frames.
const int _inputTimeoutUs = 16000;
const int _outputTimeoutUs = 0;

// ── Library + bindings (loaded lazily on first use; Android only) ────────────

final MediaCodecBindings _mc =
    MediaCodecBindings(ffi.DynamicLibrary.open('libmediandk.so'));

bool _ok(media_status_t s) => s == media_status_t.AMEDIA_OK;

// ── Output value types ──────────────────────────────────────────────────────

/// One encoded access unit. For H.264 this is an Annex B byte-stream with
/// SPS/PPS already prepended on key frames; for VP8/VP9 it is the raw frame.
final class EncodedVideoUnit {
  final Uint8List data;
  final int ptsUs;
  final bool keyframe;
  const EncodedVideoUnit(this.data, this.ptsUs, this.keyframe);
}

/// One decoded frame as packed I420.
final class DecodedI420 {
  final Uint8List data;
  final int width;
  final int height;
  final int ptsUs;
  const DecodedI420(this.data, this.width, this.height, this.ptsUs);
}

/// Turns one raw encoder output buffer into an [EncodedVideoUnit]. [flags] is
/// the `AMediaCodecBufferInfo.flags`; [codecConfig] is the most recent
/// CODEC_CONFIG blob the codec emitted (null until/unless one is seen — VP8/VP9
/// never emit one). Codec-specific logic (H.264 SPS/PPS prepend, key-frame
/// detection) lives in the implementation passed by each backend.
typedef VideoUnitFinisher = EncodedVideoUnit Function(
    Uint8List bytes, int flags, int ptsUs, Uint8List? codecConfig);

// ── Colour conversion (pure Dart, unit-testable) ────────────────────────────

/// Packed I420 (`w*h` Y, then `w/2*h/2` U, then V) → packed NV12.
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

// ── Small FFI scratch helpers ───────────────────────────────────────────────

ffi.Pointer<ffi.Char> _utf8(String s) => s.toNativeUtf8().cast<ffi.Char>();

// ── Encoder ─────────────────────────────────────────────────────────────────

final class MediaCodecVideoEncoder {
  final ffi.Pointer<AMediaCodec> _codec;
  final int _width;
  final int _height;
  final int _inputColorFormat; // 19 (planar) or 21 (semi-planar)
  final VideoUnitFinisher _finishUnit;
  Uint8List? _csd; // CODEC_CONFIG blob (e.g. H.264 SPS+PPS); null for VP8/VP9

  // Reusable FFI scratch, allocated once and freed in close(), so the
  // per-frame hot path doesn't churn the C heap (mirrors the OpenH264 backend).
  final ffi.Pointer<ffi.Size> _sizePtr = pkgffi.calloc<ffi.Size>();
  final ffi.Pointer<AMediaCodecBufferInfo> _info =
      pkgffi.calloc<AMediaCodecBufferInfo>();

  MediaCodecVideoEncoder._(this._codec, this._width, this._height,
      this._inputColorFormat, this._finishUnit);

  /// Creates and starts an encoder for [mime]. Tries NV12 (best hardware
  /// compatibility) first, then planar I420 (no conversion; reliable on the
  /// emulator's software codec). Throws [StateError] if neither configures.
  static MediaCodecVideoEncoder create({
    required String mime,
    required int width,
    required int height,
    required int bitrate,
    required int fps,
    required int keyframeIntervalSec,
    required VideoUnitFinisher finishUnit,
  }) {
    Object? lastErr;
    for (final color in const [
      _colorFormatYUV420SemiPlanar,
      _colorFormatYUV420Planar,
    ]) {
      final mimeC = _utf8(mime);
      final codec = _mc.AMediaCodec_createEncoderByType(mimeC);
      pkgffi.malloc.free(mimeC);
      if (codec == ffi.nullptr) {
        lastErr = 'AMediaCodec_createEncoderByType($mime) returned null';
        continue;
      }
      final fmt = _buildEncoderFormat(
          mime, width, height, bitrate, fps, keyframeIntervalSec, color);
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
      return MediaCodecVideoEncoder._(codec, width, height, color, finishUnit);
    }
    throw StateError('MediaCodec encoder creation failed ($mime): $lastErr');
  }

  static ffi.Pointer<AMediaFormat> _buildEncoderFormat(String mime, int width,
      int height, int bitrate, int fps, int keyframeIntervalSec, int color) {
    final fmt = _mc.AMediaFormat_new();
    final mimeC = _utf8(mime);
    _mc.AMediaFormat_setString(fmt, _mc.AMEDIAFORMAT_KEY_MIME, mimeC);
    pkgffi.malloc.free(mimeC);
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
  List<EncodedVideoUnit> encode(Uint8List i420, int ptsUs) {
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

  List<EncodedVideoUnit> _drain() {
    final out = <EncodedVideoUnit>[];
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
          _csd = bytes; // codec config (H.264 SPS+PPS); emitted once
        } else {
          out.add(_finishUnit(bytes, flags, pts, _csd));
        }
      }
      _mc.AMediaCodec_releaseOutputBuffer(_codec, idx, false);
    }
    return out;
  }

  void close() {
    _mc.AMediaCodec_stop(_codec);
    _mc.AMediaCodec_delete(_codec);
    pkgffi.calloc.free(_sizePtr);
    pkgffi.calloc.free(_info);
  }
}

// ── Decoder ─────────────────────────────────────────────────────────────────

final class MediaCodecVideoDecoder {
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

  MediaCodecVideoDecoder._(this._codec, this._width, this._height);

  /// Creates and starts a decoder for [mime]. No csd is passed — H.264 SPS/PPS
  /// arrive in-band on key frames (the encoder prepends them); VP8/VP9 frames
  /// are self-describing. Throws [StateError] on failure.
  static MediaCodecVideoDecoder create({
    required String mime,
    required int width,
    required int height,
  }) {
    final mimeC = _utf8(mime);
    final codec = _mc.AMediaCodec_createDecoderByType(mimeC);
    pkgffi.malloc.free(mimeC);
    if (codec == ffi.nullptr) {
      throw StateError('AMediaCodec_createDecoderByType($mime) returned null');
    }
    final fmt = _mc.AMediaFormat_new();
    final m2 = _utf8(mime);
    _mc.AMediaFormat_setString(fmt, _mc.AMEDIAFORMAT_KEY_MIME, m2);
    pkgffi.malloc.free(m2);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_WIDTH, width);
    _mc.AMediaFormat_setInt32(fmt, _mc.AMEDIAFORMAT_KEY_HEIGHT, height);
    final cfg =
        _mc.AMediaCodec_configure(codec, fmt, ffi.nullptr, ffi.nullptr, 0);
    _mc.AMediaFormat_delete(fmt);
    if (!_ok(cfg)) {
      _mc.AMediaCodec_delete(codec);
      throw StateError('AMediaCodec_configure (decoder, $mime) failed: $cfg');
    }
    if (!_ok(_mc.AMediaCodec_start(codec))) {
      _mc.AMediaCodec_delete(codec);
      throw StateError('AMediaCodec_start (decoder, $mime) failed');
    }
    return MediaCodecVideoDecoder._(codec, width, height);
  }

  /// Decodes one compressed access unit, returning any frames now available.
  List<DecodedI420> decode(Uint8List frame, int ptsUs) {
    final idx = _mc.AMediaCodec_dequeueInputBuffer(_codec, _inputTimeoutUs);
    if (idx >= 0) {
      final buf = _mc.AMediaCodec_getInputBuffer(_codec, idx, _sizePtr);
      if (buf != ffi.nullptr && _sizePtr.value >= frame.length) {
        buf.asTypedList(frame.length).setAll(0, frame);
        _mc.AMediaCodec_queueInputBuffer(
            _codec, idx, 0, frame.length, ptsUs, 0);
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
