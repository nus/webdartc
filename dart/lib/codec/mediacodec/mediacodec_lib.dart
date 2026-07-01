/// Single shared handle to the NDK MediaCodec library (`libmediandk.so`),
/// Android only. Every MediaCodec backend, helper, and probe binds against this
/// one [MediaCodecBindings] instead of each opening the library itself.
///
/// Lazy: a top-level `final` is initialised on first access, so `libmediandk.so`
/// is only `dlopen`'d when a MediaCodec path actually runs — importing this on a
/// non-Android platform costs nothing.
library;

import 'dart:ffi' as ffi;

import 'bindings.g.dart';

final MediaCodecBindings mediaCodecLib =
    MediaCodecBindings(ffi.DynamicLibrary.open('libmediandk.so'));
