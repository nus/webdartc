/// Opus codec registration entry point.
library;

import '../codec_registry.dart';
import 'opus_decoder_backend.dart';
import 'opus_encoder_backend.dart';

/// Registers Opus encoder and decoder backends under the codec key `opus`.
void registerOpusCodec() {
  CodecRegistry.registerAudioEncoder('opus', OpusEncoderBackend.new);
  CodecRegistry.registerAudioDecoder('opus', OpusDecoderBackend.new);
}
