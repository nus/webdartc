import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

/// Concrete track exercising the shared MediaStreamTrack machinery. A real
/// capture track is macOS-only (AVFoundation FFI), so the base behaviour is
/// covered here through a minimal in-memory implementation.
final class _TestTrack extends MediaStreamTrack {
  @override
  final String id;
  @override
  final String kind;
  final MediaTrackSettings _settings;
  bool _ended = false;

  _TestTrack({
    this.id = 'track-1',
    this.kind = 'audio',
    MediaTrackSettings settings = const MediaTrackSettings(),
  }) : _settings = settings;

  @override
  String get label => 'test';

  @override
  bool enabled = true;

  @override
  MediaStreamTrackState get readyState =>
      _ended ? MediaStreamTrackState.ended : MediaStreamTrackState.live;

  @override
  MediaTrackSettings getSettings() => _settings;

  @override
  MediaStreamTrack clone() => _TestTrack(id: id, kind: kind, settings: _settings);

  @override
  void stop() {
    if (_ended) return;
    _ended = true;
    notifyEnded();
  }

  @override
  Stream<VideoFrame> get onVideoFrame => throw UnsupportedError('audio');
  @override
  Stream<AudioData> get onAudioData => const Stream<AudioData>.empty();
}

void main() {
  group('MediaStreamTrack — ended', () {
    test('onEnded fires once when the track is stopped', () async {
      final track = _TestTrack();
      var endedCount = 0;
      track.onEnded.listen((_) => endedCount++);

      expect(track.readyState, MediaStreamTrackState.live);
      track.stop();
      expect(track.readyState, MediaStreamTrackState.ended);

      await Future<void>.delayed(Duration.zero);
      expect(endedCount, 1);
    });

    test('stop is idempotent — onEnded fires only once', () async {
      final track = _TestTrack();
      var endedCount = 0;
      track.onEnded.listen((_) => endedCount++);

      track.stop();
      track.stop();
      track.stop();

      await Future<void>.delayed(Duration.zero);
      expect(endedCount, 1);
    });
  });

  group('MediaStreamTrack — muted / mute / unmute', () {
    test('setMuted toggles muted and fires mute/unmute', () async {
      final track = _TestTrack();
      final events = <String>[];
      track.onMute.listen((_) => events.add('mute'));
      track.onUnmute.listen((_) => events.add('unmute'));

      expect(track.muted, isFalse);
      track.setMuted(true);
      expect(track.muted, isTrue);
      track.setMuted(false);
      expect(track.muted, isFalse);

      await Future<void>.delayed(Duration.zero);
      expect(events, ['mute', 'unmute']);
    });

    test('setMuted to the same value is a no-op', () async {
      final track = _TestTrack();
      final events = <String>[];
      track.onMute.listen((_) => events.add('mute'));

      track.setMuted(true);
      track.setMuted(true); // no second event
      await Future<void>.delayed(Duration.zero);
      expect(events, ['mute']);
    });

    test('setMuted after end is ignored', () async {
      final track = _TestTrack();
      track.stop();
      expect(() => track.setMuted(true), returnsNormally);
      expect(track.muted, isFalse);
    });

    test('muted is independent of enabled', () {
      final track = _TestTrack();
      track.enabled = false;
      expect(track.muted, isFalse); // app-controlled enabled ≠ source muted
    });
  });

  group('MediaStreamTrack — getSettings', () {
    test('base track returns an empty settings snapshot', () {
      final s = _TestTrack().getSettings();
      expect(s.width, isNull);
      expect(s.sampleRate, isNull);
    });

    test('a track surfaces its configured settings', () {
      final video = _TestTrack(
        kind: 'video',
        settings: const MediaTrackSettings(
            deviceId: 'cam0', width: 1280, height: 720, frameRate: 30),
      );
      final s = video.getSettings();
      expect(s.deviceId, 'cam0');
      expect(s.width, 1280);
      expect(s.height, 720);
      expect(s.frameRate, 30);
      expect(s.channelCount, isNull); // audio field unset on a video track
    });
  });
}
