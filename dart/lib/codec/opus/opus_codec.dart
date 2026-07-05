/// Opus codec descriptor + registration entry point.
library;

import 'package:ffi/ffi.dart' as pkgffi;

import '../../rtp/packetizer.dart';
import '../audio_codec.dart';
import '../codec_descriptor.dart';
import '_libopus.dart' as libopus;
import 'mediacodec_opus_decoder_backend.dart';
import 'mediacodec_opus_encoder_backend.dart';
import 'opus_decoder_backend.dart';
import 'opus_encoder_backend.dart';

/// Opus: bundled libopus everywhere except Android, which goes through
/// Android MediaCodec only (no libopus fallback) and registers nothing when
/// the device lacks an Opus codec (the encoder needs API 29+) —
/// `MediaEngine.forPlatform` then drops Opus from the SDP so it is never
/// negotiated.
final AudioCodecDescriptor opusDescriptor = AudioCodecDescriptor(
  key: AudioCodecName.opus,
  bundled: const AudioBackendPair(
    encoder: OpusEncoderBackend.new,
    decoder: OpusDecoderBackend.new,
  ),
  android: const AudioBackendPair(
    encoder: MediaCodecOpusEncoderBackend.new,
    decoder: MediaCodecOpusDecoderBackend.new,
  ),
  depacketizer: OpusDepacketizer.new,
);

/// Registers Opus encoder and decoder backends under the codec key `opus`.
/// See [opusDescriptor] for the per-platform backend choice.
void registerOpusCodec() => registerCodec(opusDescriptor);

/// Returns the bundled libopus's `opus_get_version_string()` (e.g.
/// "libopus 1.6.1" or "libopus 1.6.1-fixed"). Useful for asserting which
/// libopus build is loaded after a `dart/third_party/opus` submodule bump.
String opusLibraryVersion() {
  return libopus.opusGetVersionString().cast<pkgffi.Utf8>().toDartString();
}
