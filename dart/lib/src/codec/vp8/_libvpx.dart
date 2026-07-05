/// Bindings for the `webdartc_vp8_*` wrapper API exposed by
/// `dart/src/webdartc_vp8.{h,c}`.
///
/// libvpx is statically linked into `webdartc_vp8.dylib` (built by
/// `dart/hook/build.dart` from the `dart/third_party/libvpx/`
/// submodule). The only symbols exported from that dylib are the
/// `webdartc_vp8_*` functions below; libvpx's own `vpx_*` symbols are
/// hidden so they can't collide with another libvpx loaded elsewhere
/// in the process.
@ffi.DefaultAsset('package:webdartc/codec/vp8/webdartc_vp8.dart')
library;

import 'dart:ffi' as ffi;

/// Opaque encoder handle. Returned by [vp8EncoderCreate], destroyed by
/// [vp8EncoderDestroy].
final class WebdartcVp8Encoder extends ffi.Opaque {}

/// One encoded packet drained from the encoder. Owned by the C side
/// until [vp8OutputFree] is called.
final class WebdartcVp8Output extends ffi.Opaque {}

@ffi.Native<
    ffi.Pointer<WebdartcVp8Encoder> Function(
        ffi.Int, ffi.Int, ffi.Int, ffi.Int)>(
    symbol: 'webdartc_vp8_encoder_create')
external ffi.Pointer<WebdartcVp8Encoder> vp8EncoderCreate(
    int width, int height, int targetBitrateKbps, int kfMaxDist);

@ffi.Native<ffi.Void Function(ffi.Pointer<WebdartcVp8Encoder>)>(
    symbol: 'webdartc_vp8_encoder_destroy')
external void vp8EncoderDestroy(ffi.Pointer<WebdartcVp8Encoder> enc);

@ffi.Native<
    ffi.Int Function(
        ffi.Pointer<WebdartcVp8Encoder>,
        ffi.Pointer<ffi.Uint8>,
        ffi.Pointer<ffi.Uint8>,
        ffi.Pointer<ffi.Uint8>,
        ffi.Int,
        ffi.Int,
        ffi.Int64,
        ffi.Int)>(symbol: 'webdartc_vp8_encoder_encode')
external int vp8EncoderEncode(
    ffi.Pointer<WebdartcVp8Encoder> enc,
    ffi.Pointer<ffi.Uint8> y,
    ffi.Pointer<ffi.Uint8> u,
    ffi.Pointer<ffi.Uint8> v,
    int width,
    int height,
    int ptsUs,
    int forceKeyframe);

@ffi.Native<
    ffi.Pointer<WebdartcVp8Output> Function(
        ffi.Pointer<WebdartcVp8Encoder>)>(
    symbol: 'webdartc_vp8_encoder_drain_one')
external ffi.Pointer<WebdartcVp8Output> vp8EncoderDrainOne(
    ffi.Pointer<WebdartcVp8Encoder> enc);

@ffi.Native<ffi.Pointer<ffi.Uint8> Function(ffi.Pointer<WebdartcVp8Output>)>(
    symbol: 'webdartc_vp8_output_data')
external ffi.Pointer<ffi.Uint8> vp8OutputData(
    ffi.Pointer<WebdartcVp8Output> out);

@ffi.Native<ffi.Size Function(ffi.Pointer<WebdartcVp8Output>)>(
    symbol: 'webdartc_vp8_output_size')
external int vp8OutputSize(ffi.Pointer<WebdartcVp8Output> out);

@ffi.Native<ffi.Int64 Function(ffi.Pointer<WebdartcVp8Output>)>(
    symbol: 'webdartc_vp8_output_pts_us')
external int vp8OutputPtsUs(ffi.Pointer<WebdartcVp8Output> out);

@ffi.Native<ffi.Int Function(ffi.Pointer<WebdartcVp8Output>)>(
    symbol: 'webdartc_vp8_output_is_keyframe')
external int vp8OutputIsKeyframe(ffi.Pointer<WebdartcVp8Output> out);

@ffi.Native<ffi.Void Function(ffi.Pointer<WebdartcVp8Output>)>(
    symbol: 'webdartc_vp8_output_free')
external void vp8OutputFree(ffi.Pointer<WebdartcVp8Output> out);

@ffi.Native<ffi.Pointer<ffi.Char> Function()>(
    symbol: 'webdartc_vp8_get_version_string')
external ffi.Pointer<ffi.Char> vp8GetVersionString();

// ── Decoder ──────────────────────────────────────────────────────────

/// Opaque decoder handle.
final class WebdartcVp8Decoder extends ffi.Opaque {}

/// Decoded I420 frame. Owned by C until [vp8FrameFree].
final class WebdartcVp8Frame extends ffi.Opaque {}

@ffi.Native<ffi.Pointer<WebdartcVp8Decoder> Function()>(
    symbol: 'webdartc_vp8_decoder_create')
external ffi.Pointer<WebdartcVp8Decoder> vp8DecoderCreate();

@ffi.Native<ffi.Void Function(ffi.Pointer<WebdartcVp8Decoder>)>(
    symbol: 'webdartc_vp8_decoder_destroy')
external void vp8DecoderDestroy(ffi.Pointer<WebdartcVp8Decoder> dec);

@ffi.Native<
    ffi.Int Function(ffi.Pointer<WebdartcVp8Decoder>,
        ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Int64)>(
    symbol: 'webdartc_vp8_decoder_decode')
external int vp8DecoderDecode(
    ffi.Pointer<WebdartcVp8Decoder> dec,
    ffi.Pointer<ffi.Uint8> data,
    int size,
    int ptsUs);

@ffi.Native<ffi.Pointer<WebdartcVp8Frame> Function(
    ffi.Pointer<WebdartcVp8Decoder>)>(
    symbol: 'webdartc_vp8_decoder_drain_one')
external ffi.Pointer<WebdartcVp8Frame> vp8DecoderDrainOne(
    ffi.Pointer<WebdartcVp8Decoder> dec);

@ffi.Native<ffi.Pointer<ffi.Uint8> Function(ffi.Pointer<WebdartcVp8Frame>)>(
    symbol: 'webdartc_vp8_frame_data')
external ffi.Pointer<ffi.Uint8> vp8FrameData(
    ffi.Pointer<WebdartcVp8Frame> f);

@ffi.Native<ffi.Int Function(ffi.Pointer<WebdartcVp8Frame>)>(
    symbol: 'webdartc_vp8_frame_width')
external int vp8FrameWidth(ffi.Pointer<WebdartcVp8Frame> f);

@ffi.Native<ffi.Int Function(ffi.Pointer<WebdartcVp8Frame>)>(
    symbol: 'webdartc_vp8_frame_height')
external int vp8FrameHeight(ffi.Pointer<WebdartcVp8Frame> f);

@ffi.Native<ffi.Int64 Function(ffi.Pointer<WebdartcVp8Frame>)>(
    symbol: 'webdartc_vp8_frame_pts_us')
external int vp8FramePtsUs(ffi.Pointer<WebdartcVp8Frame> f);

@ffi.Native<ffi.Void Function(ffi.Pointer<WebdartcVp8Frame>)>(
    symbol: 'webdartc_vp8_frame_free')
external void vp8FrameFree(ffi.Pointer<WebdartcVp8Frame> f);
