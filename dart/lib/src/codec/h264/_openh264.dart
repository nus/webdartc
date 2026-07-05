/// `@Native` bindings for the top-level entry points of Cisco's
/// prebuilt OpenH264 dylib (`libopenh264.so.7`).
///
/// The dylib itself is downloaded by `dart/hook/build.dart` from
/// `ciscobinary.openh264.org` and registered as a code asset with the
/// id `package:webdartc/codec/h264/_openh264.dart` — the
/// [DefaultAsset] below resolves @Native lookups against it.
///
/// Only the four `WelsCreate*` / `WelsDestroy*` constructors plus
/// `WelsGetCodecVersion` are bound here. Every other call goes through
/// the `ISVCEncoderVtbl` / `ISVCDecoderVtbl` returned by those
/// constructors, defined in [openh264/bindings.g.dart]; vtable methods
/// are reached via `Pointer.asFunction`, not @Native.
@ffi.DefaultAsset('package:webdartc/codec/h264/_openh264.dart')
library;

import 'dart:ffi' as ffi;

import 'openh264/bindings.g.dart' as oh;

@ffi.Native<ffi.Int Function(ffi.Pointer<ffi.Pointer<oh.ISVCEncoder>>)>(
    symbol: 'WelsCreateSVCEncoder')
external int welsCreateSVCEncoder(
    ffi.Pointer<ffi.Pointer<oh.ISVCEncoder>> ppEncoder);

@ffi.Native<ffi.Void Function(ffi.Pointer<oh.ISVCEncoder>)>(
    symbol: 'WelsDestroySVCEncoder')
external void welsDestroySVCEncoder(ffi.Pointer<oh.ISVCEncoder> pEncoder);

@ffi.Native<ffi.Long Function(ffi.Pointer<ffi.Pointer<oh.ISVCDecoder>>)>(
    symbol: 'WelsCreateDecoder')
external int welsCreateDecoder(
    ffi.Pointer<ffi.Pointer<oh.ISVCDecoder>> ppDecoder);

@ffi.Native<ffi.Void Function(ffi.Pointer<oh.ISVCDecoder>)>(
    symbol: 'WelsDestroyDecoder')
external void welsDestroyDecoder(ffi.Pointer<oh.ISVCDecoder> pDecoder);

@ffi.Native<ffi.Void Function(ffi.Pointer<oh.OpenH264Version>)>(
    symbol: 'WelsGetCodecVersionEx')
external void welsGetCodecVersionEx(ffi.Pointer<oh.OpenH264Version> pVersion);
