/// FFI bindings for the VideoToolbox C helper (macOS/iOS).
///
/// The helper is built by `hook/build.dart` on Apple platforms. On other
/// OSes the symbols are absent and callers must gate on `Platform.isMacOS`
/// / `Platform.isIOS`.
library;

import 'dart:ffi' as ffi;

// ── Helper version ─────────────────────────────────────────────────────────

@ffi.Native<ffi.Int32 Function()>(symbol: 'webdartc_vt_helper_abi_version')
external int webdartcVtHelperAbiVersion();

// ── Encoder ────────────────────────────────────────────────────────────────

/// Opaque encoder handle.
final class WvtEncoder extends ffi.Opaque {}

/// Opaque queued output handle.
final class WvtEncoderOutput extends ffi.Opaque {}

@ffi.Native<
    ffi.Pointer<WvtEncoder> Function(
      ffi.Int32, ffi.Int32, ffi.Int32, ffi.Int32, ffi.Int32)>(
    symbol: 'wvt_encoder_create')
external ffi.Pointer<WvtEncoder> wvtEncoderCreate(
    int width, int height, int bitrate, int fps, int keyframeInterval);

@ffi.Native<
    ffi.Int32 Function(
      ffi.Pointer<WvtEncoder>,
      ffi.Pointer<ffi.Uint8>,
      ffi.Pointer<ffi.Uint8>,
      ffi.Pointer<ffi.Uint8>,
      ffi.Int32,
      ffi.Int32,
      ffi.Int64,
      ffi.Int32)>(symbol: 'wvt_encoder_encode')
external int wvtEncoderEncode(
    ffi.Pointer<WvtEncoder> enc,
    ffi.Pointer<ffi.Uint8> y,
    ffi.Pointer<ffi.Uint8> u,
    ffi.Pointer<ffi.Uint8> v,
    int yStride,
    int uvStride,
    int ptsUs,
    int forceKeyframe);

@ffi.Native<ffi.Pointer<WvtEncoderOutput> Function(ffi.Pointer<WvtEncoder>)>(
    symbol: 'wvt_encoder_drain_one')
external ffi.Pointer<WvtEncoderOutput> wvtEncoderDrainOne(
    ffi.Pointer<WvtEncoder> enc);

@ffi.Native<ffi.Int32 Function(ffi.Pointer<WvtEncoderOutput>)>(
    symbol: 'wvt_encoder_output_size')
external int wvtEncoderOutputSize(ffi.Pointer<WvtEncoderOutput> out);

@ffi.Native<ffi.Int32 Function(ffi.Pointer<WvtEncoderOutput>)>(
    symbol: 'wvt_encoder_output_is_keyframe')
external int wvtEncoderOutputIsKeyframe(ffi.Pointer<WvtEncoderOutput> out);

@ffi.Native<ffi.Int64 Function(ffi.Pointer<WvtEncoderOutput>)>(
    symbol: 'wvt_encoder_output_pts_us')
external int wvtEncoderOutputPtsUs(ffi.Pointer<WvtEncoderOutput> out);

@ffi.Native<ffi.Pointer<ffi.Uint8> Function(ffi.Pointer<WvtEncoderOutput>)>(
    symbol: 'wvt_encoder_output_data')
external ffi.Pointer<ffi.Uint8> wvtEncoderOutputData(
    ffi.Pointer<WvtEncoderOutput> out);

@ffi.Native<ffi.Void Function(ffi.Pointer<WvtEncoderOutput>)>(
    symbol: 'wvt_encoder_output_free')
external void wvtEncoderOutputFree(ffi.Pointer<WvtEncoderOutput> out);

@ffi.Native<ffi.Void Function(ffi.Pointer<WvtEncoder>)>(
    symbol: 'wvt_encoder_destroy')
external void wvtEncoderDestroy(ffi.Pointer<WvtEncoder> enc);

// ── Decoder ────────────────────────────────────────────────────────────────

/// Opaque decoder handle.
final class WvtDecoder extends ffi.Opaque {}

/// Opaque decoded frame handle.
final class WvtDecodedFrame extends ffi.Opaque {}

@ffi.Native<ffi.Pointer<WvtDecoder> Function()>(symbol: 'wvt_decoder_create')
external ffi.Pointer<WvtDecoder> wvtDecoderCreate();

@ffi.Native<
    ffi.Int32 Function(
      ffi.Pointer<WvtDecoder>,
      ffi.Pointer<ffi.Uint8>,
      ffi.Int32,
      ffi.Int64)>(symbol: 'wvt_decoder_decode')
external int wvtDecoderDecode(
    ffi.Pointer<WvtDecoder> dec,
    ffi.Pointer<ffi.Uint8> annexB,
    int annexBSize,
    int ptsUs);

@ffi.Native<ffi.Pointer<WvtDecodedFrame> Function(ffi.Pointer<WvtDecoder>)>(
    symbol: 'wvt_decoder_drain_one')
external ffi.Pointer<WvtDecodedFrame> wvtDecoderDrainOne(
    ffi.Pointer<WvtDecoder> dec);

@ffi.Native<ffi.Int32 Function(ffi.Pointer<WvtDecodedFrame>)>(
    symbol: 'wvt_decoded_frame_width')
external int wvtDecodedFrameWidth(ffi.Pointer<WvtDecodedFrame> f);

@ffi.Native<ffi.Int32 Function(ffi.Pointer<WvtDecodedFrame>)>(
    symbol: 'wvt_decoded_frame_height')
external int wvtDecodedFrameHeight(ffi.Pointer<WvtDecodedFrame> f);

@ffi.Native<ffi.Int64 Function(ffi.Pointer<WvtDecodedFrame>)>(
    symbol: 'wvt_decoded_frame_pts_us')
external int wvtDecodedFramePtsUs(ffi.Pointer<WvtDecodedFrame> f);

@ffi.Native<ffi.Int32 Function(ffi.Pointer<WvtDecodedFrame>)>(
    symbol: 'wvt_decoded_frame_size')
external int wvtDecodedFrameSize(ffi.Pointer<WvtDecodedFrame> f);

@ffi.Native<ffi.Pointer<ffi.Uint8> Function(ffi.Pointer<WvtDecodedFrame>)>(
    symbol: 'wvt_decoded_frame_data')
external ffi.Pointer<ffi.Uint8> wvtDecodedFrameData(
    ffi.Pointer<WvtDecodedFrame> f);

@ffi.Native<ffi.Void Function(ffi.Pointer<WvtDecodedFrame>)>(
    symbol: 'wvt_decoded_frame_free')
external void wvtDecodedFrameFree(ffi.Pointer<WvtDecodedFrame> f);

@ffi.Native<ffi.Void Function(ffi.Pointer<WvtDecoder>)>(
    symbol: 'wvt_decoder_destroy')
external void wvtDecoderDestroy(ffi.Pointer<WvtDecoder> dec);
