/// VP8 video encoder backend powered by libvpx.
///
/// Registers with [CodecRegistry] via [registerVp8Codec]. Implements
/// [VideoEncoderBackend] so the generic W3C-style [VideoEncoder] front-end
/// can drive it.
library;

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../codec_registry.dart';
import '../video_codec.dart';
import 'libvpx_bindings.g.dart' as vpx;

ffi.DynamicLibrary _openLibvpx() {
  final candidates = Platform.isMacOS
      ? const ['libvpx.dylib', 'libvpx.9.dylib', 'libvpx.8.dylib']
      : Platform.isWindows
          ? const ['vpx.dll']
          : const ['libvpx.so.9', 'libvpx.so.8', 'libvpx.so.7', 'libvpx.so'];
  Object? lastError;
  for (final name in candidates) {
    try {
      return ffi.DynamicLibrary.open(name);
    } catch (e) {
      lastError = e;
    }
  }
  throw StateError('Could not load libvpx ($candidates): $lastError');
}

final vpx.LibVpxBindings _lib = vpx.LibVpxBindings(_openLibvpx());

/// Registers the VP8 encoder backend under the codec key `vp8`.
void registerVp8Codec() {
  CodecRegistry.registerVideoEncoder('vp8', Vp8EncoderBackend.new);
}

/// VP8 encoder backend wrapping libvpx's VP8 encoder.
final class Vp8EncoderBackend implements VideoEncoderBackend {
  ffi.Pointer<vpx.vpx_codec_ctx_t>? _ctx;
  ffi.Pointer<vpx.vpx_image_t>? _img;
  VideoDecoderConfig? _decoderConfig;

  void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?)? _onOutput;
  void Function(Object)? _onError;

  int _width = 0;
  int _height = 0;
  int _pts = 0;

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

    final cfg = pkgffi.calloc<vpx.vpx_codec_enc_cfg_t>();
    final iface = _lib.vpx_codec_vp8_cx();
    final defaultRes = _lib.vpx_codec_enc_config_default(iface, cfg, 0);
    if (defaultRes != vpx.vpx_codec_err_t.VPX_CODEC_OK) {
      pkgffi.calloc.free(cfg);
      throw StateError('vpx_codec_enc_config_default failed: $defaultRes');
    }
    cfg.ref.g_w = _width;
    cfg.ref.g_h = _height;
    cfg.ref.g_timebase.num = 1;
    cfg.ref.g_timebase.den = fps;
    cfg.ref.rc_target_bitrate = bitrateKbps;
    cfg.ref.g_error_resilient = 1;
    cfg.ref.kf_max_dist = fps * 4; // keyframe every ~4s

    final ctx = pkgffi.calloc<vpx.vpx_codec_ctx_t>();
    final initRes = _lib.vpx_codec_enc_init_ver(
      ctx, iface, cfg, 0, vpx.VPX_ENCODER_ABI_VERSION,
    );
    pkgffi.calloc.free(cfg);
    if (initRes != vpx.vpx_codec_err_t.VPX_CODEC_OK) {
      final msg = _lib.vpx_codec_err_to_string(initRes)
          .cast<pkgffi.Utf8>()
          .toDartString();
      pkgffi.calloc.free(ctx);
      throw StateError('vpx_codec_enc_init failed: $msg');
    }

    _ctx = ctx;
    _img = pkgffi.calloc<vpx.vpx_image_t>();
    _pts = 0;
    _decoderConfig = VideoDecoderConfig(
      codec: 'vp8',
      codedWidth: _width,
      codedHeight: _height,
    );
  }

  @override
  void encode(VideoFrame frame, {bool keyFrame = false}) {
    final ctx = _ctx;
    final img = _img;
    if (ctx == null || img == null) {
      _onError?.call(StateError('Encoder not configured'));
      return;
    }
    if (frame.format != VideoPixelFormat.i420) {
      _onError?.call(StateError('VP8 encoder requires I420 input'));
      return;
    }
    if (frame.codedWidth != _width || frame.codedHeight != _height) {
      _onError?.call(StateError(
          'Frame size mismatch: expected ${_width}x$_height, got ${frame.codedWidth}x${frame.codedHeight}'));
      return;
    }

    final totalSize = frame.data.length;
    final native = pkgffi.calloc<ffi.UnsignedChar>(totalSize);
    native.cast<ffi.Uint8>().asTypedList(totalSize).setAll(0, frame.data);

    try {
      _lib.vpx_img_wrap(
        img,
        vpx.vpx_img_fmt.VPX_IMG_FMT_I420,
        _width,
        _height,
        1,
        native,
      );

      final flags = keyFrame ? vpx.VPX_EFLAG_FORCE_KF : 0;
      final res = _lib.vpx_codec_encode(
        ctx, img, _pts, 1, flags, vpx.VPX_DL_REALTIME,
      );
      if (res != vpx.vpx_codec_err_t.VPX_CODEC_OK) {
        _onError?.call(StateError('vpx_codec_encode failed: $res'));
        return;
      }

      _drainPackets(frame.timestamp);
    } finally {
      pkgffi.calloc.free(native);
    }
    _pts++;
  }

  void _drainPackets(int timestamp) {
    final ctx = _ctx!;
    final iter = pkgffi.calloc<vpx.vpx_codec_iter_t>();
    iter.value = ffi.nullptr;
    try {
      while (true) {
        final pkt = _lib.vpx_codec_get_cx_data(ctx, iter);
        if (pkt == ffi.nullptr) break;
        if (pkt.ref.kind !=
            vpx.vpx_codec_cx_pkt_kind.VPX_CODEC_CX_FRAME_PKT) {
          continue;
        }
        final framePkt = pkt.ref.data.frame;
        final sz = framePkt.sz;
        final bytes = Uint8List.fromList(
          framePkt.buf.cast<ffi.Uint8>().asTypedList(sz),
        );
        final isKey = (framePkt.flags & vpx.VPX_FRAME_IS_KEY) != 0;
        _onOutput?.call(
          EncodedVideoChunk(
            type: isKey
                ? EncodedVideoChunkType.key
                : EncodedVideoChunkType.delta,
            timestamp: timestamp,
            data: bytes,
          ),
          isKey
              ? EncodedVideoChunkMetadata(decoderConfig: _decoderConfig)
              : null,
        );
      }
    } finally {
      pkgffi.calloc.free(iter);
    }
  }

  @override
  Future<void> flush() async {
    final ctx = _ctx;
    if (ctx == null) return;
    final res = _lib.vpx_codec_encode(
      ctx, ffi.nullptr, _pts, 1, 0, vpx.VPX_DL_REALTIME,
    );
    if (res == vpx.vpx_codec_err_t.VPX_CODEC_OK) _drainPackets(0);
  }

  @override
  void reset() => close();

  @override
  void close() {
    if (_ctx != null) {
      _lib.vpx_codec_destroy(_ctx!);
      pkgffi.calloc.free(_ctx!);
      _ctx = null;
    }
    if (_img != null) {
      pkgffi.calloc.free(_img!);
      _img = null;
    }
  }
}
