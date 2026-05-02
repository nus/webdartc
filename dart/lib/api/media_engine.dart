/// Codec / RTP header-extension registry shared across all
/// [PeerConnection]s created by a [WebdartcApi].
///
/// Mirrors Pion's `webrtc.MediaEngine`. Phase 1 ships with an empty
/// scaffold so the `WebdartcApi(mediaEngine: ...)` plumbing exists;
/// codec registration (`registerDefaultCodecs`, `registerCodec`,
/// `registerHeaderExtension`) lands in a follow-up.
final class MediaEngine {
  const MediaEngine();
}
