/// Declarative codec descriptors — the single source of truth for what each
/// bundled codec provides: which encoder/decoder backend to register per
/// platform tier, and its RTP packetizer/depacketizer factories.
///
/// Each bundled codec defines one descriptor next to its `registerXxxCodec()`
/// entry point (vp8_codec.dart, vp9_codec.dart, h264_encoder_backend.dart,
/// opus_codec.dart); `default_codecs.dart` collects them into
/// `bundledCodecDescriptors`, and `codec_support.dart` resolves send/receive
/// capability and RTP payload-format factories from the same table.
library;

import 'dart:io' show Platform;

import '../rtp/packetizer.dart';
import 'codec_registry.dart';
import 'platform_codecs.dart';

/// Encoder + decoder factory pair for one video backend tier.
final class VideoBackendPair {
  final VideoEncoderFactory encoder;
  final VideoDecoderFactory decoder;
  const VideoBackendPair({required this.encoder, required this.decoder});
}

/// Encoder + decoder factory pair for one audio backend tier.
final class AudioBackendPair {
  final AudioEncoderFactory encoder;
  final AudioDecoderFactory decoder;
  const AudioBackendPair({required this.encoder, required this.decoder});
}

/// One bundled codec's capabilities. [registerCodec] turns a descriptor into
/// the [CodecRegistry] registrations appropriate for the current platform.
sealed class CodecDescriptor {
  /// The [CodecRegistry] key (lower-case WebCodecs name: 'vp8', 'opus', …).
  final String key;
  const CodecDescriptor({required this.key});
}

final class VideoCodecDescriptor extends CodecDescriptor {
  /// Bundled software backends (libvpx / OpenH264) — used everywhere no
  /// platform tier below applies.
  final VideoBackendPair bundled;

  /// macOS/iOS override (H.264 VideoToolbox); null = use [bundled] there.
  final VideoBackendPair? apple;

  /// Android MediaCodec backends. Registered only when the device actually
  /// provides the codec ([platformCodecAvailable]) — there is no bundled
  /// fallback on Android, and `MediaEngine.forPlatform` drops an unavailable
  /// codec from the SDP so it is never negotiated.
  final VideoBackendPair android;

  /// RTP payload-format factories (packetizers are stateful, hence factories).
  final PayloadPacketizer Function({int maxPayloadSize}) packetizer;
  final VideoPayloadDepacketizer Function() depacketizer;

  const VideoCodecDescriptor({
    required super.key,
    required this.bundled,
    this.apple,
    required this.android,
    required this.packetizer,
    required this.depacketizer,
  });
}

final class AudioCodecDescriptor extends CodecDescriptor {
  /// Bundled software backends (libopus) — used everywhere except Android.
  final AudioBackendPair bundled;

  /// Android MediaCodec backends, gated like [VideoCodecDescriptor.android].
  final AudioBackendPair android;

  /// RTP depacketizer factory (audio payloads need no packetizer class).
  final AudioPayloadDepacketizer Function() depacketizer;

  const AudioCodecDescriptor({
    required super.key,
    required this.bundled,
    required this.android,
    required this.depacketizer,
  });
}

/// Registers [descriptor]'s encoder + decoder backends for the current
/// platform with [CodecRegistry]. On Android, a codec the device does not
/// provide ([platformCodecAvailable]) registers nothing.
void registerCodec(CodecDescriptor descriptor) {
  switch (descriptor) {
    case VideoCodecDescriptor():
      final pair = _selectVideo(descriptor);
      if (pair == null) return;
      CodecRegistry.registerVideoEncoder(descriptor.key, pair.encoder);
      CodecRegistry.registerVideoDecoder(descriptor.key, pair.decoder);
    case AudioCodecDescriptor():
      final pair = _selectAudio(descriptor);
      if (pair == null) return;
      CodecRegistry.registerAudioEncoder(descriptor.key, pair.encoder);
      CodecRegistry.registerAudioDecoder(descriptor.key, pair.decoder);
  }
}

VideoBackendPair? _selectVideo(VideoCodecDescriptor d) {
  if (Platform.isAndroid) {
    return platformCodecAvailable(d.key) ? d.android : null;
  }
  if (Platform.isMacOS || Platform.isIOS) return d.apple ?? d.bundled;
  return d.bundled;
}

AudioBackendPair? _selectAudio(AudioCodecDescriptor d) {
  if (Platform.isAndroid) {
    return platformCodecAvailable(d.key) ? d.android : null;
  }
  return d.bundled;
}
