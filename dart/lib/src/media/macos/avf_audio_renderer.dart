/// W3C-shaped audio-output sink for macOS and iOS.
///
/// The W3C spec puts sink selection on `HTMLMediaElement.setSinkId`
/// (Audio Output Devices API). webdartc has no DOM, so this class is
/// the equivalent receptacle: attach an audio [MediaStreamTrack] and
/// pick the output device via [setSinkId]. Backed by CoreAudio
/// AudioQueue through `wmd_media.m`.
library;

import 'dart:async';
import 'dart:io' show Platform;

import '../audio_data.dart';
import '../media_stream.dart';
import '../media_stream_track.dart';
import 'avf_media.dart';

class AudioRenderer {
  final int _sampleRate;
  final int _channels;
  NativeAudioRenderer? _native;
  // ignore: cancel_subscriptions
  StreamSubscription<AudioData>? _trackSub;
  String? _sinkId;
  bool _playing = false;

  /// The configured PCM format. Attached tracks must match — there's no
  /// runtime resampler yet, so a 48 kHz mono renderer can't accept
  /// 16 kHz or stereo input.
  AudioRenderer({int sampleRate = 48000, int channels = 1})
      : _sampleRate = sampleRate,
        _channels = channels {
    if (!Platform.isMacOS && !Platform.isIOS) {
      throw UnsupportedError(
          'AudioRenderer is only available on macOS and iOS '
          '(current platform: ${Platform.operatingSystem})');
    }
    final n = NativeAudioRenderer.create(
        sampleRate: sampleRate, channels: channels);
    if (n == null) {
      throw StateError('Failed to allocate native AudioRenderer');
    }
    _native = n;
  }

  int get sampleRate => _sampleRate;
  int get channels => _channels;
  String? get sinkId => _sinkId;
  bool get isPlaying => _playing;

  /// Pick the output device. `null` restores the system default. Device
  /// IDs match those returned by `MediaDevices.enumerateDevices()` for
  /// `kind == 'audiooutput'`.
  ///
  /// Synchronous despite the `Future` return — kept Future-typed to
  /// match the W3C `HTMLMediaElement.setSinkId` shape so callers can
  /// `await` it.
  Future<void> setSinkId(String? deviceId) {
    final n = _requireNative();
    // AudioQueue requires the queue to be paused before
    // kAudioQueueProperty_CurrentDevice is changed. If the property set
    // fails after stop, resume so the renderer doesn't silently mute.
    final wasPlaying = _playing;
    if (wasPlaying) {
      n.stop();
      _playing = false;
    }
    if (!n.setSink(deviceId)) {
      if (wasPlaying) play();
      throw StateError('Failed to set sink to "${deviceId ?? "(default)"}"');
    }
    _sinkId = deviceId;
    if (wasPlaying) play();
    return Future.value();
  }

  /// Convenience: attach the first audio track of [stream].
  void attachStream(MediaStream stream) {
    final audio = stream.getAudioTracks();
    if (audio.isEmpty) {
      throw ArgumentError('Stream has no audio tracks');
    }
    attachTrack(audio.first);
  }

  void attachTrack(MediaStreamTrack track) {
    if (track.kind != 'audio') {
      throw ArgumentError(
          'attachTrack requires kind=="audio", got ${track.kind}');
    }
    detachTrack();
    _trackSub = track.onAudioData.listen(_onAudioData);
    play();
  }

  void detachTrack() {
    final sub = _trackSub;
    if (sub != null) {
      unawaited(sub.cancel());
      _trackSub = null;
    }
  }

  /// Push a single AudioData frame directly (bypasses [attachTrack]).
  /// Useful for synthetic sources / tests.
  void push(AudioData data) => _onAudioData(data);

  void play() {
    if (_playing) return;
    if (!_requireNative().start()) {
      throw StateError('AudioQueue start failed');
    }
    _playing = true;
  }

  void pause() {
    if (!_playing) return;
    _requireNative().stop();
    _playing = false;
  }

  void close() {
    detachTrack();
    _playing = false;
    final n = _native;
    if (n != null) {
      n.release();
      _native = null;
    }
  }

  void _onAudioData(AudioData data) {
    final n = _native;
    if (n == null) return;
    if (data.format != AudioSampleFormat.s16) {
      throw UnsupportedError(
          'AudioRenderer requires s16 frames, got ${data.format}');
    }
    // Lazy-start so callers using [push] directly don't have to remember
    // to call [play] — matches `HTMLAudioElement` semantics where
    // setting srcObject is enough.
    if (!_playing) play();
    n.push(data.data);
  }

  NativeAudioRenderer _requireNative() {
    final n = _native;
    if (n == null) throw StateError('AudioRenderer has been closed');
    return n;
  }
}
