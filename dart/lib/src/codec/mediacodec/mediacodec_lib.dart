/// Single shared handle to the NDK MediaCodec library (`libmediandk.so`),
/// Android only. Every MediaCodec backend, helper, and probe binds against this
/// one [MediaCodecBindings] instead of each opening the library itself.
///
/// Lazy: a top-level `final` is initialised on first access, so `libmediandk.so`
/// is only `dlopen`'d when a MediaCodec path actually runs — importing this on a
/// non-Android platform costs nothing.
library;

import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart' as pkgffi;

import 'bindings.g.dart';

final MediaCodecBindings mediaCodecLib =
    MediaCodecBindings(ffi.DynamicLibrary.open('libmediandk.so'));

// Constants and tiny helpers shared by every MediaCodec helper (audio + video).
// The numeric values are stable android.media.MediaCodec constants the NDK does
// not export as symbols; the helpers wrap the two calls every path makes.

const int configureFlagEncode = 1; // AMediaCodec CONFIGURE_FLAG_ENCODE
const int bufferFlagCodecConfig = 2; // BUFFER_FLAG_CODEC_CONFIG
const int infoTryAgainLater = -1; // AMediaCodec dequeue sentinel

// dequeue timeouts (microseconds): output drains non-blocking (0); input waits
// briefly so a momentarily-busy codec doesn't drop frames.
const int inputTimeoutUs = 16000;
const int outputTimeoutUs = 0;

bool mediaCodecOk(media_status_t s) => s == media_status_t.AMEDIA_OK;

ffi.Pointer<ffi.Char> mediaCodecUtf8(String s) =>
    s.toNativeUtf8().cast<ffi.Char>();
