/// VP8 codec registration entry point.
library;

import 'dart:io' show Platform;

import 'package:ffi/ffi.dart' as pkgffi;

import '../codec_registry.dart';
import '../mediacodec/mediacodec_probe.dart';
import '../video_codec.dart';
import '_libvpx.dart' as libvpx;
import 'mediacodec_vp8_decoder_backend.dart';
import 'mediacodec_vp8_encoder_backend.dart';
import 'vp8_decoder_backend.dart';
import 'vp8_encoder_backend.dart';

const String _vp8Mime = 'video/x-vnd.on2.vp8';

/// Registers VP8 encoder and decoder backends under the codec key `vp8`.
///
/// On Android, prefers Android MediaCodec when the device actually provides a
/// VP8 encoder / decoder (probed independently), falling back to the bundled
/// libvpx otherwise. Everywhere else, uses libvpx.
void registerVp8Codec() {
  final useMcEncoder = Platform.isAndroid && mediaCodecHasEncoder(_vp8Mime);
  final useMcDecoder = Platform.isAndroid && mediaCodecHasDecoder(_vp8Mime);
  CodecRegistry.registerVideoEncoder(
    VideoCodecName.vp8,
    useMcEncoder ? MediaCodecVp8EncoderBackend.new : Vp8EncoderBackend.new,
  );
  CodecRegistry.registerVideoDecoder(
    VideoCodecName.vp8,
    useMcDecoder ? MediaCodecVp8DecoderBackend.new : Vp8DecoderBackend.new,
  );
}

/// Returns the bundled libvpx's `vpx_codec_version_str()` (e.g.
/// "v1.16.0"). Useful for asserting which libvpx build is loaded after
/// a `dart/third_party/libvpx` submodule bump.
String vp8LibraryVersion() {
  return libvpx.vp8GetVersionString().cast<pkgffi.Utf8>().toDartString();
}
