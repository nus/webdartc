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

  /// JPEG / MJPEG payload (RFC 2435). Not in [defaultVideoCodecs] because
  /// no major browser implements RFC 2435 — they parse the SDP, fail to
  /// match `JPEG/90000` against their internal codec table, and drop the
  /// PT silently from the answer. Useful in webdartc↔webdartc topologies
  /// where the sender wants to forward a camera's native MJPEG bytes
  /// without re-encoding.
  ///
  /// PT 26 is statically assigned by RFC 3551 §6 and so doesn't strictly
  /// need an `a=rtpmap` line, but the SDP builder emits one anyway for
  /// peers that filter by name.
  ///
  /// ```dart
  /// final pc = PeerConnection(
  ///   configuration: const PeerConnectionConfiguration(),
  ///   mediaEngine: MediaEngine(
  ///     videoCodecs: [MediaEngine.jpegVideoCodec, ...MediaEngine.defaultVideoCodecs],
  ///   ),
  /// );
  /// pc.addTransceiver('video', preferredCodecs: ['JPEG']);
  /// ```
  static const RtpCodec jpegVideoCodec = RtpCodec(
    payloadType: 26,
    name: 'JPEG',
    clockRate: 90000,
  );

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
