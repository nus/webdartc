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
import 'dart:typed_data';

import '../crypto/csprng.dart';
import 'audio_data.dart';
import 'media_stream_track.dart';
import 'video_frame.dart';

/// Base for tracks fed by a remote RTP receive pipeline. Holds the shared
/// `MediaStreamTrack` lifecycle and lazy-activation hooks; subclasses supply
/// the media kind, the typed media stream, the disabled-state behaviour, and a
/// clone factory.
abstract base class ReceiverTrack<T> extends MediaStreamTrack {
  final String _id;
  final String _label;
  bool _enabled = true;

  /// Called when the first consumer subscribes to the media stream — the owner
  /// uses this to start the decode pipeline lazily.
  void Function()? onActivate;

  /// Called when the last consumer unsubscribes — the owner may pause it.
  void Function()? onDeactivate;

  late final StreamController<T> _events = StreamController<T>.broadcast(
    onListen: () => onActivate?.call(),
    onCancel: () => onDeactivate?.call(),
  );
  StreamSubscription<T>? _cloneSub;

  ReceiverTrack({required String id, required String label})
      : _id = id,
        _label = label;

  /// Push a decoded media item from the receive pipeline. Dropped once stopped;
  /// when disabled, [whenDisabled] decides what (if anything) is emitted.
  void deliver(T item) {
    if (_events.isClosed) return;
    if (_enabled) {
      _events.add(item);
      return;
    }
    final muted = whenDisabled(item);
    if (muted != null) _events.add(muted);
  }

  /// What a disabled track emits for [item]: null to drop it (video), or a
  /// silenced replacement (audio). W3C: a disabled track renders black/silence
  /// rather than ending the stream.
  T? whenDisabled(T item);

  /// A fresh same-type track sharing nothing — used by [clone].
  ReceiverTrack<T> newInstance(String id, String label);

  /// Whether anyone is currently consuming (drives lazy activation).
  bool get hasListener => _events.hasListener;

  @override
  String get id => _id;

  @override
  String get label => _label;

  @override
  bool get enabled => _enabled;

  @override
  set enabled(bool value) => _enabled = value;

  @override
  MediaStreamTrackState get readyState => _events.isClosed
      ? MediaStreamTrackState.ended
      : MediaStreamTrackState.live;

  /// A clone shares this track's decoded-media source (W3C clones share the
  /// underlying source) with independent `enabled`/`stop` state.
  @override
  ReceiverTrack<T> clone() {
    final c = newInstance(Csprng.randomHex(16), _label);
    c._cloneSub = _events.stream.listen(c.deliver);
    return c;
  }

  @override
  void stop() {
    if (_events.isClosed) return;
    unawaited(_cloneSub?.cancel());
    _cloneSub = null;
    unawaited(_events.close());
    notifyEnded();
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
  Stream<VideoFrame> get onVideoFrame => _events.stream;

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
  AudioData whenDisabled(AudioData data) => AudioData(
        // Silence of the same shape, keeping downstream playout cadence intact.
        format: data.format,
        sampleRate: data.sampleRate,
        numberOfChannels: data.numberOfChannels,
        numberOfFrames: data.numberOfFrames,
        timestamp: data.timestamp,
        data: Uint8List(data.data.length),
      );

  @override
  ReceiverAudioTrack newInstance(String id, String label) =>
      ReceiverAudioTrack(id: id, label: label);

  @override
  String get kind => 'audio';

  @override
  Stream<AudioData> get onAudioData => _events.stream;

  @override
  Stream<VideoFrame> get onVideoFrame =>
      throw UnsupportedError('Audio track does not produce video frames');
}
