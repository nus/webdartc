/// Bulk registration of the codec backends webdartc bundles.
library;

import 'codec_descriptor.dart';
import 'h264/h264_encoder_backend.dart' show h264Descriptor;
import 'opus/opus_codec.dart' show opusDescriptor;
import 'vp8/vp8_codec.dart' show vp8Descriptor;
import 'vp9/vp9_codec.dart' show vp9Descriptor;

/// Descriptors for every codec webdartc bundles, in registration order. The
/// declarative table behind [registerDefaultCodecs] and `codec_support.dart`'s
/// capability probes / RTP payload-format factories.
final List<CodecDescriptor> bundledCodecDescriptors = [
  vp8Descriptor,
  vp9Descriptor,
  h264Descriptor,
  opusDescriptor,
];

/// Registers every codec backend bundled with webdartc (VP8, VP9, H.264, Opus)
/// in one call.
///
/// Registration only stores factory closures in [CodecRegistry]; the native
/// libraries (libvpx, OpenH264/VideoToolbox, libopus) are loaded lazily via
/// `DynamicLibrary.open` only when a codec is actually instantiated — i.e. when
/// media for that codec is sent or received. Calling this therefore costs
/// nothing for, say, a data-channel-only connection.
///
/// [PeerConnection] calls this automatically so the W3C receive path
/// (`onTrack` → `track.onVideoFrame`) works out of the box. Applications that
/// want to control which backends are available can disable the automatic call
/// (`autoRegisterCodecs: false` on `PeerConnection` / `Webdartc`) and register
/// a subset themselves.
///
/// Idempotent and cheap to call repeatedly: the bulk registration runs once per
/// isolate (every `PeerConnection` would otherwise re-register the same
/// factories).
void registerDefaultCodecs() {
  if (_registered) return;
  _registered = true;
  for (final descriptor in bundledCodecDescriptors) {
    registerCodec(descriptor);
  }
}

bool _registered = false;
