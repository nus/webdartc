/// VP9 codec descriptor + registration entry point.
library;

import 'package:ffi/ffi.dart' as pkgffi;

import '../../rtp/packetizer.dart';
import '../codec_descriptor.dart';
import '../mediacodec/mediacodec_video_decoder_backend.dart';
import '../mediacodec/mediacodec_video_encoder_backend.dart';
import '../mediacodec/mime_types.dart';
import '../video_codec.dart';
import '_libvpx9.dart' as libvpx9;
import 'vp9_decoder_backend.dart';
import 'vp9_encoder_backend.dart';

/// VP9: bundled libvpx everywhere except Android, which goes through Android
/// MediaCodec only (no libvpx fallback) and registers nothing when the device
/// lacks a VP9 codec — `MediaEngine.forPlatform` then drops VP9 from the SDP
/// so it is never negotiated.
final VideoCodecDescriptor vp9Descriptor = VideoCodecDescriptor(
  key: VideoCodecName.vp9,
  bundled: const VideoBackendPair(
    encoder: Vp9EncoderBackend.new,
    decoder: Vp9DecoderBackend.new,
  ),
  android: VideoBackendPair(
    encoder: () => MediaCodecVideoEncoderBackend(vp9Mime, VideoCodecName.vp9),
    decoder: () => MediaCodecVideoDecoderBackend(vp9Mime),
  ),
  packetizer: Vp9Packetizer.new,
  depacketizer: Vp9Depacketizer.new,
);

/// Registers VP9 encoder and decoder backends under the codec key `vp9`.
/// See [vp9Descriptor] for the per-platform backend choice.
void registerVp9Codec() => registerCodec(vp9Descriptor);

/// Returns the bundled libvpx's `vpx_codec_version_str()`. Both VP8 and
/// VP9 link the same libvpx archive, so this should match
/// `vp8LibraryVersion()`.
String vp9LibraryVersion() {
  return libvpx9.vp9GetVersionString().cast<pkgffi.Utf8>().toDartString();
}
