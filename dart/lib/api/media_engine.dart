import '../codec/platform_codecs.dart';
import '../sdp/parser.dart' show RtpCodec;

/// Catalog of RTP codec capabilities that this peer is willing to negotiate
/// in SDP. Decoupled from the encoder/decoder backend registry: an entry
/// here describes what is *advertised on the wire*, not what can actually be
/// encoded or decoded by the library's convenience [VideoEncoder] /
/// [VideoDecoder] / [AudioEncoder] / [AudioDecoder] front-ends.
///
/// This separation is what enables packet-passthrough use cases (relays,
/// SFU-style forwarding, pre-encoded byte streaming) — a caller can list a
/// codec here and consume / produce its RTP payload directly via
/// [PeerConnection.onRtpPacket] and [RtpSender.sendRtp] without ever
/// registering an encoder or decoder backend.
///
/// Construct with `const` for shared engines, or `const MediaEngine()` to
/// pick up the WebRTC-typical defaults (VP8, H.264 Constrained Baseline 3.1,
/// Opus 48 kHz stereo). Pass `[]` for either field to opt out completely.
///
/// ```dart
/// const rtc = Webdartc(
///   mediaEngine: MediaEngine(
///     videoCodecs: [...MediaEngine.defaultVideoCodecs, customAv1Codec],
///   ),
/// );
/// ```
final class MediaEngine {
  /// Audio codecs offered/answered for any audio m=line. Ordered by
  /// preference (first = most preferred).
  final List<RtpCodec> audioCodecs;

  /// Video codecs offered/answered for any video m=line. Ordered by
  /// preference (first = most preferred).
  final List<RtpCodec> videoCodecs;

  const MediaEngine({
    this.audioCodecs = defaultAudioCodecs,
    this.videoCodecs = defaultVideoCodecs,
  });

  /// MediaEngine that advertises no codecs. Use when the application wants
  /// to register every codec capability explicitly.
  static const MediaEngine empty =
      MediaEngine(audioCodecs: [], videoCodecs: []);

  /// The default codecs, narrowed to those this platform can actually encode
  /// *and* decode (see [platformCodecAvailable]). On Android a codec without a
  /// MediaCodec component — e.g. Opus on API < 29 — is dropped here so it never
  /// reaches the SDP offer/answer; elsewhere this equals the full defaults.
  /// This is the engine [PeerConnection] uses when the app doesn't supply one;
  /// an app that passes its own [MediaEngine] is taken verbatim (so
  /// packet-passthrough advertising is unaffected).
  factory MediaEngine.forPlatform() => MediaEngine(
        videoCodecs: [
          for (final c in defaultVideoCodecs)
            if (platformCodecAvailable(c.name)) c,
        ],
        audioCodecs: [
          for (final c in defaultAudioCodecs)
            if (platformCodecAvailable(c.name)) c,
        ],
      );

  static const List<RtpCodec> defaultVideoCodecs = [
    RtpCodec(
      payloadType: 96,
      name: 'VP8',
      clockRate: 90000,
      rtcpFb: ['nack', 'nack pli', 'ccm fir', 'goog-remb'],
    ),
    RtpCodec(
      payloadType: 102,
      name: 'H264',
      clockRate: 90000,
      fmtpParams: 'level-asymmetry-allowed=1;packetization-mode=1;'
          'profile-level-id=42e01f',
      rtcpFb: ['nack', 'nack pli', 'ccm fir', 'goog-remb'],
    ),
  ];

  static const List<RtpCodec> defaultAudioCodecs = [
    RtpCodec(
      payloadType: 111,
      name: 'opus',
      clockRate: 48000,
      channels: 2,
      fmtpParams: 'minptime=10;useinbandfec=1',
    ),
  ];

  /// Codec names (case-preserved, registration order) — handy for passing
  /// to SDP builders that filter by name.
  List<String> get audioCodecNames => [for (final c in audioCodecs) c.name];
  List<String> get videoCodecNames => [for (final c in videoCodecs) c.name];

  /// Filter [audioCodecs] to those matching [preferredNames] in the given
  /// order; case-insensitive. Names not present in this engine are skipped
  /// silently. When [preferredNames] is null, returns the full list.
  List<RtpCodec> resolveAudioCodecs(List<String>? preferredNames) =>
      _filter(audioCodecs, preferredNames);

  List<RtpCodec> resolveVideoCodecs(List<String>? preferredNames) =>
      _filter(videoCodecs, preferredNames);

  static List<RtpCodec> _filter(
      List<RtpCodec> all, List<String>? preferredNames) {
    if (preferredNames == null) return all;
    return [
      for (final name in preferredNames)
        for (final c in all)
          if (c.name.toLowerCase() == name.toLowerCase()) c,
    ];
  }
}
