/// VP9 codec registration entry point.
library;

import 'dart:io' show Platform;

import 'package:ffi/ffi.dart' as pkgffi;

import '../codec_registry.dart';
import '../mediacodec/mediacodec_video_decoder_backend.dart';
import '../mediacodec/mediacodec_video_encoder_backend.dart';
import '../mediacodec/mime_types.dart';
import '../platform_codecs.dart';
import '../video_codec.dart';
import '_libvpx9.dart' as libvpx9;
import 'vp9_decoder_backend.dart';
import 'vp9_encoder_backend.dart';

/// Registers VP9 encoder and decoder backends under the codec key `vp9`.
///
/// On Android, VP9 goes through Android MediaCodec only (no libvpx fallback):
/// if the device provides a VP9 codec ([platformCodecAvailable]) the MediaCodec
/// backends are registered, otherwise nothing is — and `MediaEngine.forPlatform`
/// drops VP9 from the SDP so it is never negotiated. Everywhere else, uses the
/// bundled libvpx.
void registerVp9Codec() {
  if (Platform.isAndroid) {
    if (platformCodecAvailable(VideoCodecName.vp9)) {
      CodecRegistry.registerVideoEncoder(VideoCodecName.vp9,
          () => MediaCodecVideoEncoderBackend(vp9Mime, VideoCodecName.vp9));
      CodecRegistry.registerVideoDecoder(
          VideoCodecName.vp9, () => MediaCodecVideoDecoderBackend(vp9Mime));
    }
  } else {
    CodecRegistry.registerVideoEncoder(
        VideoCodecName.vp9, Vp9EncoderBackend.new);
    CodecRegistry.registerVideoDecoder(
        VideoCodecName.vp9, Vp9DecoderBackend.new);
  }
}

/// Returns the bundled libvpx's `vpx_codec_version_str()`. Both VP8 and
/// VP9 link the same libvpx archive, so this should match
/// `vp8LibraryVersion()`.
String vp9LibraryVersion() {
  return libvpx9.vp9GetVersionString().cast<pkgffi.Utf8>().toDartString();
}
