/// VP8 codec descriptor + registration entry point.
library;

import 'package:ffi/ffi.dart' as pkgffi;

import '../../rtp/packetizer.dart';
import '../codec_descriptor.dart';
import '../mediacodec/mediacodec_video_decoder_backend.dart';
import '../mediacodec/mediacodec_video_encoder_backend.dart';
import '../mediacodec/mime_types.dart';
import '../video_codec.dart';
import '_libvpx.dart' as libvpx;
import 'vp8_decoder_backend.dart';
import 'vp8_encoder_backend.dart';

/// VP8: bundled libvpx everywhere except Android, which goes through Android
/// MediaCodec only (no libvpx fallback) and registers nothing when the device
/// lacks a VP8 codec — `MediaEngine.forPlatform` then drops VP8 from the SDP
/// so it is never negotiated.
final VideoCodecDescriptor vp8Descriptor = VideoCodecDescriptor(
  key: VideoCodecName.vp8,
  bundled: const VideoBackendPair(
    encoder: Vp8EncoderBackend.new,
    decoder: Vp8DecoderBackend.new,
  ),
  android: VideoBackendPair(
    encoder: () => MediaCodecVideoEncoderBackend(vp8Mime, VideoCodecName.vp8),
    decoder: () => MediaCodecVideoDecoderBackend(vp8Mime),
  ),
  packetizer: Vp8Packetizer.new,
  depacketizer: Vp8Depacketizer.new,
);

/// Registers VP8 encoder and decoder backends under the codec key `vp8`.
/// See [vp8Descriptor] for the per-platform backend choice.
void registerVp8Codec() => registerCodec(vp8Descriptor);

/// Returns the bundled libvpx's `vpx_codec_version_str()` (e.g.
/// "v1.16.0"). Useful for asserting which libvpx build is loaded after
/// a `dart/third_party/libvpx` submodule bump.
String vp8LibraryVersion() {
  return libvpx.vp8GetVersionString().cast<pkgffi.Utf8>().toDartString();
}
