/// VP8 codec registration entry point.
library;

import 'dart:io' show Platform;

import 'package:ffi/ffi.dart' as pkgffi;

import '../codec_registry.dart';
import '../mediacodec/mediacodec_video_decoder_backend.dart';
import '../mediacodec/mime_types.dart';
import '../platform_codecs.dart';
import '../video_codec.dart';
import '_libvpx.dart' as libvpx;
import 'mediacodec_vp8_encoder_backend.dart';
import 'vp8_decoder_backend.dart';
import 'vp8_encoder_backend.dart';

/// Registers VP8 encoder and decoder backends under the codec key `vp8`.
///
/// On Android, VP8 goes through Android MediaCodec only (no libvpx fallback):
/// if the device provides a VP8 codec ([platformCodecAvailable]) the MediaCodec
/// backends are registered, otherwise nothing is — and `MediaEngine.forPlatform`
/// drops VP8 from the SDP so it is never negotiated. Everywhere else, uses the
/// bundled libvpx.
void registerVp8Codec() {
  if (Platform.isAndroid) {
    if (platformCodecAvailable(VideoCodecName.vp8)) {
      CodecRegistry.registerVideoEncoder(
          VideoCodecName.vp8, MediaCodecVp8EncoderBackend.new);
      CodecRegistry.registerVideoDecoder(
          VideoCodecName.vp8, () => MediaCodecVideoDecoderBackend(vp8Mime));
    }
  } else {
    CodecRegistry.registerVideoEncoder(
        VideoCodecName.vp8, Vp8EncoderBackend.new);
    CodecRegistry.registerVideoDecoder(
        VideoCodecName.vp8, Vp8DecoderBackend.new);
  }
}

/// Returns the bundled libvpx's `vpx_codec_version_str()` (e.g.
/// "v1.16.0"). Useful for asserting which libvpx build is loaded after
/// a `dart/third_party/libvpx` submodule bump.
String vp8LibraryVersion() {
  return libvpx.vp8GetVersionString().cast<pkgffi.Utf8>().toDartString();
}
