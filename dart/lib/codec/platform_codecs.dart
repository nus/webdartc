/// Which codecs this platform can actually encode *and* decode — the single
/// source of truth shared by codec registration (which backend to register) and
/// SDP advertising ([MediaEngine.forPlatform]), so the two never disagree.
///
/// On Android the answer depends on what MediaCodec the device ships (probed at
/// runtime, since e.g. the Opus encoder only exists on API 29+ and VP8/VP9
/// encoders are device-dependent); everywhere else the bundled codecs
/// (libvpx / libopus / OpenH264 / VideoToolbox) cover everything.
library;

import 'dart:io' show Platform;

import 'mediacodec/mediacodec_probe.dart';
import 'mediacodec/mime_types.dart';

/// Probe results are stable for the process lifetime, so cache them: each probe
/// instantiates and destroys a MediaCodec, which we only want to do once.
final Map<String, bool> _cache = {};

/// Whether [codecName] (`vp8`, `h264`, `opus`, …, case-insensitive) can be both
/// encoded and decoded on this platform. A codec that returns false is dropped
/// from the default SDP offer/answer and has no backend registered.
bool platformCodecAvailable(String codecName) {
  final key = codecName.toLowerCase();
  return _cache[key] ??= _compute(key);
}

bool _compute(String codec) {
  // Non-Android platforms bundle a software codec for everything we advertise.
  if (!Platform.isAndroid) return true;
  switch (codec) {
    // H.264/AVC is a mandatory Android codec and has no bundled Android
    // fallback (Cisco ships no Android OpenH264 binary), so it is always taken
    // to be available via MediaCodec.
    case 'h264':
      return true;
    case 'vp8':
      return mediaCodecHasEncoder(vp8Mime) && mediaCodecHasDecoder(vp8Mime);
    case 'vp9':
      return mediaCodecHasEncoder(vp9Mime) && mediaCodecHasDecoder(vp9Mime);
    // The Opus encoder only exists on API 29+, so API 24–28 devices — which have
    // the decoder but no encoder — drop Opus entirely (no libopus fallback).
    case 'opus':
      return mediaCodecHasEncoder(opusMime) && mediaCodecHasDecoder(opusMime);
    // Unknown codecs (e.g. an app's custom MediaEngine entry) are not gated.
    default:
      return true;
  }
}

/// Test seam: force [codecName]'s availability (or pass null to clear the cached
/// value so the next query re-probes). Lets host tests exercise the SDP gate
/// without an Android device. Not for production use.
void debugSetPlatformCodecAvailability(String codecName, bool? available) {
  final key = codecName.toLowerCase();
  if (available == null) {
    _cache.remove(key);
  } else {
    _cache[key] = available;
  }
}
