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
library;

// Core types
export 'core/result.dart';
export 'core/types.dart';

// W3C PeerConnection API (data_channel.dart and events.dart are parts of peer_connection.dart)
export 'peer_connection/peer_connection.dart';

// SDP
export 'sdp/parser.dart';

// ICE
export 'ice/candidate.dart';
export 'ice/state_machine.dart';

// SCTP
export 'sctp/state_machine.dart';
export 'sctp/dcep.dart';

// Crypto (for testing / advanced use)
export 'crypto/csprng.dart';
export 'crypto/hmac_sha1.dart';
export 'crypto/sha1.dart';
export 'crypto/sha256.dart';
export 'crypto/hkdf.dart';
export 'crypto/aes_cm.dart';
export 'crypto/aes_gcm.dart';
export 'crypto/ecdh.dart';
export 'crypto/ecdsa.dart';

// STUN
export 'stun/message.dart';
export 'stun/parser.dart';
export 'stun/builder.dart';
export 'stun/crc32c.dart';

// SRTP
export 'srtp/context.dart';

// RTP/RTCP
export 'rtp/parser.dart';
export 'rtp/rtp_transport.dart';

// Media (W3C Media Capture & Streams)
export 'media/video_frame.dart';
export 'media/audio_data.dart';
export 'media/media_stream_track.dart';
export 'media/media_stream.dart';
export 'media/media_devices.dart';
export 'media/fake_video_source.dart';

// Codec (W3C WebCodecs)
export 'codec/video_codec.dart';
export 'codec/audio_codec.dart';
export 'codec/codec_registry.dart';
export 'codec/vp8/vp8_encoder_backend.dart';
export 'codec/h264/h264_encoder_backend.dart';
