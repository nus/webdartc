/// VP8 codec registration entry point.
library;

import 'package:ffi/ffi.dart' as pkgffi;

import '../codec_registry.dart';
import '_libvpx.dart' as libvpx;
import 'vp8_decoder_backend.dart';
import 'vp8_encoder_backend.dart';

/// Registers VP8 encoder and decoder backends under the codec key `vp8`.
void registerVp8Codec() {
  CodecRegistry.registerVideoEncoder('vp8', Vp8EncoderBackend.new);
  CodecRegistry.registerVideoDecoder('vp8', Vp8DecoderBackend.new);
}

/// Returns the bundled libvpx's `vpx_codec_version_str()` (e.g.
/// "v1.16.0"). Useful for asserting which libvpx build is loaded after
/// a `dart/third_party/libvpx` submodule bump.
String vp8LibraryVersion() {
  return libvpx.vp8GetVersionString().cast<pkgffi.Utf8>().toDartString();
}
