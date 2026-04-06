/// W3C MediaStreamTrack — represents a single audio or video track.
/// https://www.w3.org/TR/mediacapture-streams/#mediastreamtrack
library;

import 'audio_data.dart';
import 'video_frame.dart';

/// Track state per W3C spec.
enum MediaStreamTrackState { live, ended }

/// Abstract media track — subclassed for local (capture) and remote (RTP) sources.
abstract class MediaStreamTrack {
  /// Unique identifier for this track.
  String get id;

  /// Track kind: 'audio' or 'video'.
  String get kind;

  /// Human-readable label (e.g. device name).
  String get label;

  /// Whether the track is enabled (muted if false).
  bool get enabled;
  set enabled(bool value);

  /// Current state of the track.
  MediaStreamTrackState get readyState;

  /// Create a clone of this track.
  MediaStreamTrack clone();

  /// Stop the track (transitions to ended).
  void stop();

  /// Stream of decoded video frames (video tracks only).
  /// Throws [UnsupportedError] on audio tracks.
  Stream<VideoFrame> get onVideoFrame;

  /// Stream of decoded audio samples (audio tracks only).
  /// Throws [UnsupportedError] on video tracks.
  Stream<AudioData> get onAudioData;
}
