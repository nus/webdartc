/// Opus codec registration entry point.
library;

import 'dart:io' show Platform;

import 'package:ffi/ffi.dart' as pkgffi;

import '../audio_codec.dart';
import '../codec_registry.dart';
import '../platform_codecs.dart';
import '_libopus.dart' as libopus;
import 'mediacodec_opus_decoder_backend.dart';
import 'mediacodec_opus_encoder_backend.dart';
import 'opus_decoder_backend.dart';
import 'opus_encoder_backend.dart';

/// Registers Opus encoder and decoder backends under the codec key `opus`.
///
/// On Android, Opus goes through Android MediaCodec only (no libopus fallback):
/// if the device provides an Opus codec ([platformCodecAvailable] — the encoder
/// needs API 29+) the MediaCodec backends are registered, otherwise nothing is
/// — and `MediaEngine.forPlatform` drops Opus from the SDP so it is never
/// negotiated. Everywhere else, uses the bundled libopus.
void registerOpusCodec() {
  if (Platform.isAndroid) {
    if (platformCodecAvailable(AudioCodecName.opus)) {
      CodecRegistry.registerAudioEncoder(
          AudioCodecName.opus, MediaCodecOpusEncoderBackend.new);
      CodecRegistry.registerAudioDecoder(
          AudioCodecName.opus, MediaCodecOpusDecoderBackend.new);
    }
  } else {
    CodecRegistry.registerAudioEncoder(
        AudioCodecName.opus, OpusEncoderBackend.new);
    CodecRegistry.registerAudioDecoder(
        AudioCodecName.opus, OpusDecoderBackend.new);
  }
}

/// Returns the bundled libopus's `opus_get_version_string()` (e.g.
/// "libopus 1.6.1" or "libopus 1.6.1-fixed"). Useful for asserting which
/// libopus build is loaded after a `dart/third_party/opus` submodule bump.
String opusLibraryVersion() {
  return libopus.opusGetVersionString().cast<pkgffi.Utf8>().toDartString();
}
