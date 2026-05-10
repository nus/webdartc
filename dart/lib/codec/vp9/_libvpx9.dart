/// Bindings for the `webdartc_vp9_*` wrapper API exposed by
/// `dart/src/webdartc_vp9.{h,c}`.
///
/// libvpx is statically linked into `webdartc_vp9.dylib` (the same
/// vpx-install-* archive that libwebdartc_vp8 also pulls from). Only
/// the `webdartc_vp9_*` symbols below are exported; libvpx's own
/// `vpx_*` symbols are hidden so they can't collide with another libvpx
/// loaded elsewhere in the process — including the sibling
/// `webdartc_vp8.dylib` which links the same libvpx.a.
@ffi.DefaultAsset('package:webdartc/codec/vp9/webdartc_vp9.dart')
library;

import 'dart:ffi' as ffi;

/// Opaque encoder handle.
final class WebdartcVp9Encoder extends ffi.Opaque {}

/// One encoded packet drained from the encoder. Owned by C until
/// [vp9OutputFree].
final class WebdartcVp9Output extends ffi.Opaque {}

/// Opaque decoder handle.
final class WebdartcVp9Decoder extends ffi.Opaque {}

/// Decoded I420 frame. Owned by C until [vp9FrameFree].
final class WebdartcVp9Frame extends ffi.Opaque {}

@ffi.Native<
    ffi.Pointer<WebdartcVp9Encoder> Function(
        ffi.Int, ffi.Int, ffi.Int, ffi.Int)>(
    symbol: 'webdartc_vp9_encoder_create')
external ffi.Pointer<WebdartcVp9Encoder> vp9EncoderCreate(
    int width, int height, int targetBitrateKbps, int kfMaxDist);

@ffi.Native<ffi.Void Function(ffi.Pointer<WebdartcVp9Encoder>)>(
    symbol: 'webdartc_vp9_encoder_destroy')
external void vp9EncoderDestroy(ffi.Pointer<WebdartcVp9Encoder> enc);

@ffi.Native<
    ffi.Int Function(
        ffi.Pointer<WebdartcVp9Encoder>,
        ffi.Pointer<ffi.Uint8>,
        ffi.Pointer<ffi.Uint8>,
        ffi.Pointer<ffi.Uint8>,
        ffi.Int,
        ffi.Int,
        ffi.Int64,
        ffi.Int)>(symbol: 'webdartc_vp9_encoder_encode')
external int vp9EncoderEncode(
    ffi.Pointer<WebdartcVp9Encoder> enc,
    ffi.Pointer<ffi.Uint8> y,
    ffi.Pointer<ffi.Uint8> u,
    ffi.Pointer<ffi.Uint8> v,
    int width,
    int height,
    int ptsUs,
    int forceKeyframe);

@ffi.Native<
    ffi.Pointer<WebdartcVp9Output> Function(
        ffi.Pointer<WebdartcVp9Encoder>)>(
    symbol: 'webdartc_vp9_encoder_drain_one')
external ffi.Pointer<WebdartcVp9Output> vp9EncoderDrainOne(
    ffi.Pointer<WebdartcVp9Encoder> enc);

@ffi.Native<ffi.Pointer<ffi.Uint8> Function(ffi.Pointer<WebdartcVp9Output>)>(
    symbol: 'webdartc_vp9_output_data')
external ffi.Pointer<ffi.Uint8> vp9OutputData(
    ffi.Pointer<WebdartcVp9Output> out);

@ffi.Native<ffi.Size Function(ffi.Pointer<WebdartcVp9Output>)>(
    symbol: 'webdartc_vp9_output_size')
external int vp9OutputSize(ffi.Pointer<WebdartcVp9Output> out);

@ffi.Native<ffi.Int64 Function(ffi.Pointer<WebdartcVp9Output>)>(
    symbol: 'webdartc_vp9_output_pts_us')
external int vp9OutputPtsUs(ffi.Pointer<WebdartcVp9Output> out);

@ffi.Native<ffi.Int Function(ffi.Pointer<WebdartcVp9Output>)>(
    symbol: 'webdartc_vp9_output_is_keyframe')
external int vp9OutputIsKeyframe(ffi.Pointer<WebdartcVp9Output> out);

@ffi.Native<ffi.Void Function(ffi.Pointer<WebdartcVp9Output>)>(
    symbol: 'webdartc_vp9_output_free')
external void vp9OutputFree(ffi.Pointer<WebdartcVp9Output> out);

@ffi.Native<ffi.Pointer<ffi.Char> Function()>(
    symbol: 'webdartc_vp9_get_version_string')
external ffi.Pointer<ffi.Char> vp9GetVersionString();

@ffi.Native<ffi.Pointer<WebdartcVp9Decoder> Function()>(
    symbol: 'webdartc_vp9_decoder_create')
external ffi.Pointer<WebdartcVp9Decoder> vp9DecoderCreate();

@ffi.Native<ffi.Void Function(ffi.Pointer<WebdartcVp9Decoder>)>(
    symbol: 'webdartc_vp9_decoder_destroy')
external void vp9DecoderDestroy(ffi.Pointer<WebdartcVp9Decoder> dec);

@ffi.Native<
    ffi.Int Function(ffi.Pointer<WebdartcVp9Decoder>,
        ffi.Pointer<ffi.Uint8>, ffi.Size, ffi.Int64)>(
    symbol: 'webdartc_vp9_decoder_decode')
external int vp9DecoderDecode(
    ffi.Pointer<WebdartcVp9Decoder> dec,
    ffi.Pointer<ffi.Uint8> data,
    int size,
    int ptsUs);

@ffi.Native<ffi.Pointer<WebdartcVp9Frame> Function(
    ffi.Pointer<WebdartcVp9Decoder>)>(
    symbol: 'webdartc_vp9_decoder_drain_one')
external ffi.Pointer<WebdartcVp9Frame> vp9DecoderDrainOne(
    ffi.Pointer<WebdartcVp9Decoder> dec);

@ffi.Native<ffi.Pointer<ffi.Uint8> Function(ffi.Pointer<WebdartcVp9Frame>)>(
    symbol: 'webdartc_vp9_frame_data')
external ffi.Pointer<ffi.Uint8> vp9FrameData(
    ffi.Pointer<WebdartcVp9Frame> f);

@ffi.Native<ffi.Int Function(ffi.Pointer<WebdartcVp9Frame>)>(
    symbol: 'webdartc_vp9_frame_width')
external int vp9FrameWidth(ffi.Pointer<WebdartcVp9Frame> f);

@ffi.Native<ffi.Int Function(ffi.Pointer<WebdartcVp9Frame>)>(
    symbol: 'webdartc_vp9_frame_height')
external int vp9FrameHeight(ffi.Pointer<WebdartcVp9Frame> f);

@ffi.Native<ffi.Int64 Function(ffi.Pointer<WebdartcVp9Frame>)>(
    symbol: 'webdartc_vp9_frame_pts_us')
external int vp9FramePtsUs(ffi.Pointer<WebdartcVp9Frame> f);

@ffi.Native<ffi.Void Function(ffi.Pointer<WebdartcVp9Frame>)>(
    symbol: 'webdartc_vp9_frame_free')
external void vp9FrameFree(ffi.Pointer<WebdartcVp9Frame> f);
