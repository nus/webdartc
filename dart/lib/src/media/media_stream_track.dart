/// W3C MediaStreamTrack — represents a single audio or video track.
/// https://www.w3.org/TR/mediacapture-streams/#mediastreamtrack
library;

import 'dart:async';

import 'audio_data.dart';
import 'video_frame.dart';

/// Track state per W3C spec.
enum MediaStreamTrackState { live, ended }

/// Snapshot of a track's current settings (W3C `MediaTrackSettings`).
/// Only the subset webdartc tracks populate is modelled; fields that don't
/// apply (e.g. audio fields on a video track) stay null.
final class MediaTrackSettings {
  /// Source device identifier, if known.
  final String? deviceId;

  // Video
  final int? width;
  final int? height;
  final double? frameRate;

  // Audio
  final int? sampleRate;
  final int? channelCount;

  const MediaTrackSettings({
    this.deviceId,
    this.width,
    this.height,
    this.frameRate,
    this.sampleRate,
    this.channelCount,
  });
}

/// Abstract media track — subclassed for local (capture) and remote (RTP) sources.
///
/// The W3C `ended` / `mute` / `unmute` event machinery and the `muted` state
/// live here so subclasses get them for free; a subclass signals them through
/// [notifyEnded] / [setMuted] from its source.
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

  // ── Settings (W3C getSettings) ────────────────────────────────────────────

  /// The track's current settings (W3C `getSettings()`). The base returns an
  /// empty snapshot; capture tracks override it with real device values.
  MediaTrackSettings getSettings() => const MediaTrackSettings();

  // ── ended / mute / unmute events ──────────────────────────────────────────

  final _endedController = StreamController<void>.broadcast();
  final _muteController = StreamController<void>.broadcast();
  final _unmuteController = StreamController<void>.broadcast();
  bool _muted = false;

  /// Fires once when the track ends (W3C `ended`).
  Stream<void> get onEnded => _endedController.stream;

  /// Fires when the source becomes temporarily unable to provide data
  /// (W3C `mute`).
  Stream<void> get onMute => _muteController.stream;

  /// Fires when the source resumes providing data (W3C `unmute`).
  Stream<void> get onUnmute => _unmuteController.stream;

  /// Whether the source is temporarily unable to provide media data (W3C
  /// `muted`). Distinct from [enabled], which the application controls.
  bool get muted => _muted;

  /// Update [muted] and fire `mute`/`unmute`. Idempotent; a no-op once the
  /// track has ended. Called by a subclass when its source signals a
  /// (un)mute — not part of the public W3C surface.
  void setMuted(bool value) {
    if (_muted == value || _endedController.isClosed) return;
    _muted = value;
    (value ? _muteController : _unmuteController).add(null);
  }

  /// Fire `ended` once and release the event controllers. A subclass calls
  /// this from [stop] (and whenever its source ends on its own).
  void notifyEnded() {
    if (_endedController.isClosed) return;
    _endedController.add(null);
    unawaited(_endedController.close());
    unawaited(_muteController.close());
    unawaited(_unmuteController.close());
  }
}

/// Base for tracks whose media flows through a typed broadcast stream —
/// shared by receiver tracks (pushed by the RTP decode pipeline) and
/// capture tracks (polled from a native FIFO) so the id/enabled/
/// controller/`stop()` lifecycle exists once instead of per source kind.
///
/// Not part of the W3C surface: [events] and the listener hooks are for
/// subclass wiring, not applications.
abstract base class StreamBackedTrack<TEvent> extends MediaStreamTrack {
  final String _id;
  final String _label;
  bool _enabled = true;

  StreamBackedTrack({required String id, required String label})
      : _id = id,
        _label = label;

  /// The typed media event stream backing [MediaStreamTrack.onVideoFrame] /
  /// [MediaStreamTrack.onAudioData]. Lazily activates its source:
  /// [onFirstListener] fires when the first consumer subscribes and
  /// [onLastListenerGone] when the last one leaves.
  late final StreamController<TEvent> events =
      StreamController<TEvent>.broadcast(
    onListen: onFirstListener,
    onCancel: onLastListenerGone,
  );

  /// First consumer subscribed — start the source (decode pipeline, poll
  /// timer).
  void onFirstListener() {}

  /// Last consumer unsubscribed — the source may pause.
  void onLastListenerGone() {}

  /// Release source-side resources; runs from [stop] before the event
  /// stream closes.
  void onStop() {}

  /// Whether anyone is currently consuming (drives lazy activation).
  bool get hasListener => events.hasListener;

  @override
  String get id => _id;

  @override
  String get label => _label;

  @override
  bool get enabled => _enabled;

  @override
  set enabled(bool value) => _enabled = value;

  @override
  MediaStreamTrackState get readyState => events.isClosed
      ? MediaStreamTrackState.ended
      : MediaStreamTrackState.live;

  @override
  void stop() {
    if (events.isClosed) return;
    onStop();
    unawaited(events.close());
    notifyEnded();
  }
}
