/// VP9 codec registration entry point.
library;

import 'package:ffi/ffi.dart' as pkgffi;

import '../codec_registry.dart';
import '_libvpx9.dart' as libvpx9;
import 'vp9_decoder_backend.dart';
import 'vp9_encoder_backend.dart';

/// Registers VP9 encoder and decoder backends under the codec key `vp9`.
void registerVp9Codec() {
  CodecRegistry.registerVideoEncoder('vp9', Vp9EncoderBackend.new);
  CodecRegistry.registerVideoDecoder('vp9', Vp9DecoderBackend.new);
}

/// Returns the bundled libvpx's `vpx_codec_version_str()`. Both VP8 and
/// VP9 link the same libvpx archive, so this should match
/// `vp8LibraryVersion()`.
String vp9LibraryVersion() {
  return libvpx9.vp9GetVersionString().cast<pkgffi.Utf8>().toDartString();
}
