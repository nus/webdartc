/// MediaStreamTrack subclasses backed by a remote RTP receive pipeline.
///
/// Unlike capture tracks (which poll a native FIFO on a timer), a receiver
/// track is *pushed* decoded frames by the receive pipeline via [deliver]. The
/// pipeline is expensive (depacketize + decode) so it is started lazily: the
/// broadcast controller's `onListen` fires [onActivate] when the first consumer
/// subscribes (e.g. a renderer attaches), and `onCancel` fires [onDeactivate]
/// when the last one leaves. The owning `RtpReceiver` wires those callbacks to
/// build / tear down the pipeline.
library;

import 'dart:async';

import '../crypto/csprng.dart';
import 'audio_data.dart';
import 'media_stream_track.dart';
import 'video_frame.dart';

/// Base for tracks fed by a remote RTP receive pipeline. The stream/enabled/
/// stop lifecycle comes from [StreamBackedTrack]; this adds the pipeline
/// push ([deliver]), the disabled-state hook, and the clone machinery.
abstract base class ReceiverTrack<T> extends StreamBackedTrack<T> {
  /// Called when the first consumer subscribes to the media stream — the owner
  /// uses this to start the decode pipeline lazily.
  void Function()? onActivate;

  /// Called when the last consumer unsubscribes — the owner may pause it.
  void Function()? onDeactivate;

  StreamSubscription<T>? _cloneSub;

  ReceiverTrack({required super.id, required super.label});

  @override
  void onFirstListener() => onActivate?.call();

  @override
  void onLastListenerGone() => onDeactivate?.call();

  /// Push a decoded media item from the receive pipeline. Dropped once stopped;
  /// when disabled, [whenDisabled] decides what (if anything) is emitted.
  void deliver(T item) {
    if (events.isClosed) return;
    if (enabled) {
      events.add(item);
      return;
    }
    final muted = whenDisabled(item);
    if (muted != null) events.add(muted);
  }

  /// What a disabled track emits for [item]: null to drop it (video), or a
  /// silenced replacement (audio). W3C: a disabled track renders black/silence
  /// rather than ending the stream.
  T? whenDisabled(T item);

  /// A fresh same-type track sharing nothing — used by [clone].
  ReceiverTrack<T> newInstance(String id, String label);

  /// A clone shares this track's decoded-media source (W3C clones share the
  /// underlying source) with independent `enabled`/`stop` state.
  @override
  ReceiverTrack<T> clone() {
    final c = newInstance(Csprng.randomHex(16), label);
    c._cloneSub = events.stream.listen(c.deliver);
    return c;
  }

  @override
  void onStop() {
    unawaited(_cloneSub?.cancel());
    _cloneSub = null;
  }
}

/// Video track fed by a remote RTP video stream's decoder output.
final class ReceiverVideoTrack extends ReceiverTrack<VideoFrame> {
  ReceiverVideoTrack({required super.id, super.label = 'remote video'});

  /// Push a decoded frame from the receive pipeline.
  void deliverFrame(VideoFrame frame) => deliver(frame);

  @override
  VideoFrame? whenDisabled(VideoFrame frame) => null; // drop when disabled

  @override
  ReceiverVideoTrack newInstance(String id, String label) =>
      ReceiverVideoTrack(id: id, label: label);

  @override
  String get kind => 'video';

  @override
  Stream<VideoFrame> get onVideoFrame => events.stream;

  @override
  Stream<AudioData> get onAudioData =>
      throw UnsupportedError('Video track does not produce audio data');
}

/// Audio track fed by a remote RTP audio stream's decoder output.
final class ReceiverAudioTrack extends ReceiverTrack<AudioData> {
  ReceiverAudioTrack({required super.id, super.label = 'remote audio'});

  /// Push decoded audio from the receive pipeline.
  void deliverAudio(AudioData data) => deliver(data);

  @override
  AudioData whenDisabled(AudioData data) => AudioData.silenceLike(data);

  @override
  ReceiverAudioTrack newInstance(String id, String label) =>
      ReceiverAudioTrack(id: id, label: label);

  @override
  String get kind => 'audio';

  @override
  Stream<AudioData> get onAudioData => events.stream;

  @override
  Stream<VideoFrame> get onVideoFrame =>
      throw UnsupportedError('Audio track does not produce video frames');
}
