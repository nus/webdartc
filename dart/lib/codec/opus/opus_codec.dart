/// Opus codec registration entry point.
library;

import 'package:ffi/ffi.dart' as pkgffi;

import '../audio_codec.dart';
import '../codec_registry.dart';
import '_libopus.dart' as libopus;
import 'opus_decoder_backend.dart';
import 'opus_encoder_backend.dart';

/// Registers Opus encoder and decoder backends under the codec key `opus`.
void registerOpusCodec() {
  CodecRegistry.registerAudioEncoder(AudioCodecName.opus, OpusEncoderBackend.new);
  CodecRegistry.registerAudioDecoder(AudioCodecName.opus, OpusDecoderBackend.new);
}

/// Returns the bundled libopus's `opus_get_version_string()` (e.g.
/// "libopus 1.6.1" or "libopus 1.6.1-fixed"). Useful for asserting which
/// libopus build is loaded after a `dart/third_party/opus` submodule bump.
String opusLibraryVersion() {
  return libopus.opusGetVersionString().cast<pkgffi.Utf8>().toDartString();
}
