/// Bindings for the `webdartc_opus_*` wrapper API exposed by
/// `dart/src/webdartc_opus.{h,c}`.
///
/// libopus is statically linked into `webdartc_codecs.dylib` (built by
/// `dart/hook/build.dart` from the `dart/third_party/opus/` submodule). The
/// only symbols exported from that dylib are the `webdartc_opus_*`
/// functions below; libopus's own `opus_*` symbols are hidden so they
/// can't collide with another libopus loaded elsewhere in the process.
@ffi.DefaultAsset('package:webdartc/codec/opus/webdartc_opus.dart')
library;

import 'dart:ffi' as ffi;

// Mirror libopus values (verbatim from opus_defines.h).
const int opusOk = 0;
const int opusApplicationVoip = 2048;
const int opusSetBitrateRequest = 4002;

/// Opaque handles. The wrapper layer takes care of the actual
/// `OpusEncoder` / `OpusDecoder` C types — Dart only passes pointers.
final class OpusEncoder extends ffi.Opaque {}

final class OpusDecoder extends ffi.Opaque {}

@ffi.Native<
    ffi.Pointer<OpusEncoder> Function(
        ffi.Int32, ffi.Int, ffi.Int, ffi.Pointer<ffi.Int>)>(
    symbol: 'webdartc_opus_encoder_create')
external ffi.Pointer<OpusEncoder> opusEncoderCreate(
    int sampleRate, int channels, int application, ffi.Pointer<ffi.Int> error);

@ffi.Native<ffi.Void Function(ffi.Pointer<OpusEncoder>)>(
    symbol: 'webdartc_opus_encoder_destroy')
external void opusEncoderDestroy(ffi.Pointer<OpusEncoder> st);

@ffi.Native<
    ffi.Int32 Function(ffi.Pointer<OpusEncoder>, ffi.Pointer<ffi.Int16>,
        ffi.Int, ffi.Pointer<ffi.UnsignedChar>, ffi.Int32)>(
    symbol: 'webdartc_opus_encode')
external int opusEncode(
    ffi.Pointer<OpusEncoder> st,
    ffi.Pointer<ffi.Int16> pcm,
    int frameSize,
    ffi.Pointer<ffi.UnsignedChar> data,
    int maxDataBytes);

@ffi.Native<ffi.Int Function(ffi.Pointer<OpusEncoder>, ffi.Int, ffi.Int32)>(
    symbol: 'webdartc_opus_encoder_ctl_int')
external int opusEncoderCtlInt(
    ffi.Pointer<OpusEncoder> st, int request, int value);

@ffi.Native<
    ffi.Pointer<OpusDecoder> Function(
        ffi.Int32, ffi.Int, ffi.Pointer<ffi.Int>)>(
    symbol: 'webdartc_opus_decoder_create')
external ffi.Pointer<OpusDecoder> opusDecoderCreate(
    int sampleRate, int channels, ffi.Pointer<ffi.Int> error);

@ffi.Native<ffi.Void Function(ffi.Pointer<OpusDecoder>)>(
    symbol: 'webdartc_opus_decoder_destroy')
external void opusDecoderDestroy(ffi.Pointer<OpusDecoder> st);

@ffi.Native<
    ffi.Int Function(ffi.Pointer<OpusDecoder>, ffi.Pointer<ffi.UnsignedChar>,
        ffi.Int32, ffi.Pointer<ffi.Int16>, ffi.Int, ffi.Int)>(
    symbol: 'webdartc_opus_decode')
external int opusDecode(
    ffi.Pointer<OpusDecoder> st,
    ffi.Pointer<ffi.UnsignedChar> data,
    int len,
    ffi.Pointer<ffi.Int16> pcm,
    int frameSize,
    int decodeFec);

@ffi.Native<ffi.Pointer<ffi.Char> Function()>(
    symbol: 'webdartc_opus_get_version_string')
external ffi.Pointer<ffi.Char> opusGetVersionString();
