/// webdartc — WebRTC library for Dart.
///
/// RFC-compliant, I/O-isolated implementation following W3C WebRTC API
/// (without the "RTC" prefix on public types).
///
/// Usage:
/// ```dart
/// import 'package:webdartc/webdartc.dart';
///
/// final pc = PeerConnection(configuration: PeerConnectionConfiguration());
/// final offer = await pc.createOffer();
/// await pc.setLocalDescription(offer);
/// ```
///
/// Protocol internals (crypto primitives, STUN/SRTP/DTLS state machines,
/// RTP packetizers, …) live under `src/` and are not part of the public
/// contract — import `package:webdartc/src/...` directly at your own risk.
library;

// Core types — state_machine.dart re-exports result.dart and types.dart
// (which re-exports ip_address.dart). The ProtocolError hierarchy it defines
// appears in the exported ICE/SCTP state machines' signatures.
export 'src/core/state_machine.dart';

// W3C PeerConnection API (data_channel.dart and events.dart are parts of peer_connection.dart)
export 'src/peer_connection/peer_connection.dart';

// API factory (optional; default `PeerConnection(...)` constructor still works)
export 'src/api/webdartc.dart';
export 'src/api/setting_engine.dart';
export 'src/api/media_engine.dart';
export 'src/api/stats.dart';

// SDP
export 'src/sdp/parser.dart';

// ICE (state_machine.dart re-exports candidate.dart)
export 'src/ice/state_machine.dart';

// SCTP (state_machine.dart re-exports dcep.dart)
export 'src/sctp/state_machine.dart';

// RTP packet types and payload packetizers — surfaced by the raw-RTP escape
// hatches on the W3C API (`RtpReceiver.onRtp`, `RtpSender.sendRtp`,
// `RtpSender.replacePacketSender`).
export 'src/rtp/packet.dart';
export 'src/rtp/packetizer.dart';
export 'src/rtp/rtp_transport.dart' show RtpPacketSender;

// Media (W3C Media Capture & Streams)
export 'src/media/video_frame.dart';
export 'src/media/audio_data.dart';
export 'src/media/media_stream_track.dart';
export 'src/media/receiver_track.dart';
export 'src/media/receive_pipeline.dart';
export 'src/media/media_stream.dart';
export 'src/media/media_devices.dart';
export 'src/media/fake_video_source.dart';
export 'src/media/fake_audio_source.dart';

// Codec (W3C WebCodecs)
export 'src/codec/video_codec.dart';
export 'src/codec/audio_codec.dart';
export 'src/codec/codec_registry.dart';
export 'src/codec/default_codecs.dart';
export 'src/codec/vp8/vp8_codec.dart';
export 'src/codec/vp9/vp9_codec.dart';
export 'src/codec/h264/h264_encoder_backend.dart';
export 'src/codec/opus/opus_codec.dart';
