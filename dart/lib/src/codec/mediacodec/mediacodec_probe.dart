/// Runtime probe for Android MediaCodec codec availability (Android only).
///
/// Android ships software MediaCodec components for H.264/VP8/VP9/Opus, but the
/// set varies by API level (e.g. the Opus *encoder* `c2.android.opus.encoder`
/// only exists on API 31+; many devices have no VP9 encoder). Backends use
/// these probes to prefer a MediaCodec implementation when the device actually
/// provides one and fall back to the bundled libvpx/libopus otherwise.
///
/// Callers MUST guard with `Platform.isAndroid` — these load `libmediandk.so`,
/// which only exists on Android.
library;

import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart' as pkgffi;

import 'mediacodec_lib.dart';

/// Whether the device has a MediaCodec encoder for [mime]
/// (e.g. `video/x-vnd.on2.vp8`, `audio/opus`).
bool mediaCodecHasEncoder(String mime) => _probe(mime, encoder: true);

/// Whether the device has a MediaCodec decoder for [mime].
bool mediaCodecHasDecoder(String mime) => _probe(mime, encoder: false);

/// `AMediaCodec_create{Encoder,Decoder}ByType` returns null when no component
/// supports [mime]; instantiating (without configure/start) and immediately
/// deleting is the cheapest way to ask "does this device have one?". Any
/// failure (library missing, throw) is treated as "not available" so the caller
/// falls back to the bundled codec.
bool _probe(String mime, {required bool encoder}) {
  try {
    final m = mime.toNativeUtf8().cast<ffi.Char>();
    final codec = encoder
        ? mediaCodecLib.AMediaCodec_createEncoderByType(m)
        : mediaCodecLib.AMediaCodec_createDecoderByType(m);
    pkgffi.malloc.free(m);
    if (codec == ffi.nullptr) return false;
    mediaCodecLib.AMediaCodec_delete(codec);
    return true;
  } catch (_) {
    return false;
  }
}
