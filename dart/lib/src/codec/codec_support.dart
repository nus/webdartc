/// Codec capability probe + RTP payload-format factories, resolved from the
/// bundled codec descriptor table ([bundledCodecDescriptors]).
library;

import '../rtp/packetizer.dart';
import 'codec_descriptor.dart';
import 'codec_registry.dart';
import 'default_codecs.dart';

// Keyed by the descriptors' lower-case CodecRegistry keys (exact match,
// like the switch lookups these replaced).
final Map<String, VideoCodecDescriptor> _videoByKey = {
  for (final d in bundledCodecDescriptors)
    if (d is VideoCodecDescriptor) d.key: d,
};
final Map<String, AudioCodecDescriptor> _audioByKey = {
  for (final d in bundledCodecDescriptors)
    if (d is AudioCodecDescriptor) d.key: d,
};

VideoCodecDescriptor? _video(String codecKey) => _videoByKey[codecKey];

AudioCodecDescriptor? _audio(String codecKey) => _audioByKey[codecKey];

/// A fresh [VideoPayloadDepacketizer] for [codecKey] (a lower-case
/// CodecRegistry key, e.g. `vp8` / `h264`), or null if the codec has no RTP
/// depacketizer. A new instance is returned per call since depacketizers are
/// stateful (they accumulate fragments).
VideoPayloadDepacketizer? videoDepacketizerFor(String codecKey) =>
    _video(codecKey)?.depacketizer();

/// A fresh [PayloadPacketizer] for [codecKey], or null if the codec has no
/// RTP packetizer. Send-side counterpart of [videoDepacketizerFor].
PayloadPacketizer? videoPacketizerFor(String codecKey,
        {int maxPayloadSize = 1200}) =>
    _video(codecKey)?.packetizer(maxPayloadSize: maxPayloadSize);

/// A fresh [AudioPayloadDepacketizer] for [codecKey], or null if unsupported.
/// See [videoDepacketizerFor].
AudioPayloadDepacketizer? audioDepacketizerFor(String codecKey) =>
    _audio(codecKey)?.depacketizer();

/// Whether media of [kind] ('video' | 'audio') with [codecKey] can be sent /
/// received end-to-end: a backend is registered with [CodecRegistry] *and*
/// the descriptor table provides the matching RTP payload format.
abstract final class CodecSupport {
  CodecSupport._();

  static bool canSend(String kind, String codecKey) => switch (kind) {
        'video' => CodecRegistry.hasVideoEncoder(codecKey) &&
            _video(codecKey) != null,
        'audio' => CodecRegistry.hasAudioEncoder(codecKey) &&
            _audio(codecKey) != null,
        _ => false,
      };

  static bool canReceive(String kind, String codecKey) => switch (kind) {
        'video' => CodecRegistry.hasVideoDecoder(codecKey) &&
            _video(codecKey) != null,
        'audio' => CodecRegistry.hasAudioDecoder(codecKey) &&
            _audio(codecKey) != null,
        _ => false,
      };
}
