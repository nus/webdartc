/// MediaStreamTrack subclasses backed by AVFoundation capture.
///
/// Each track polls its native FIFO queue on a timer (≈ half the frame
/// interval for video, 10 ms for audio so 20-ms PCM packets stay near
/// real-time). Polling avoids `Dart_PostCObject_DL` and keeps the
/// foreign-thread surface inside the C shim.
library;

import 'dart:async';
import 'dart:typed_data';

import '../../crypto/csprng.dart';
import '../audio_data.dart';
import '../media_stream_track.dart';
import '../video_frame.dart';
import 'avf_media.dart';

abstract base class _AvfCaptureTrack<TEvent> extends MediaStreamTrack {
  final String _id;
  final String _label;
  final Duration _pollInterval;
  bool _enabled = true;
  // Eagerly constructed so the `close_sinks` lint can trace the
  // controller's lifetime through [stop]. Polling starts when a listener
  // attaches (onListen) and ends when the last one detaches.
  late final StreamController<TEvent> _events =
      StreamController<TEvent>.broadcast(
    onListen: _ensureTimer,
    onCancel: _maybeStopTimer,
  );
  Timer? _timer;

  _AvfCaptureTrack(this._id, this._label, this._pollInterval);

  /// Pop and emit a single native frame. Returns false when the queue is
  /// empty so the drain loop can stop.
  bool _drainOne();

  /// Stop and release the underlying native capture.
  void _disposeNativeCapture();

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

  @override
  MediaStreamTrack clone() =>
      throw UnsupportedError('AvfCaptureTrack.clone is not implemented');

  @override
  void stop() {
    if (_events.isClosed) return;
    _timer?.cancel();
    _timer = null;
    _disposeNativeCapture();
    unawaited(_events.close());
  }

  void _ensureTimer() {
    _timer ??= Timer.periodic(_pollInterval, (_) => _drain());
  }

  void _maybeStopTimer() {
    if (!_events.hasListener) {
      _timer?.cancel();
      _timer = null;
    }
  }

  void _drain() {
    if (_events.isClosed) return;
    while (_drainOne()) {}
  }
}

/// Camera-backed video track. Drains the native I420 queue and emits
/// [VideoFrame]s on [onVideoFrame].
final class AvfCaptureVideoTrack extends _AvfCaptureTrack<VideoFrame> {
  final NativeVideoCapture _capture;

  AvfCaptureVideoTrack._(this._capture, super.id, super.label, super.interval);

  static AvfCaptureVideoTrack? create({
    String? deviceId,
    String label = 'camera',
    int width = 1280,
    int height = 720,
    double framerate = 30,
  }) {
    final cap = NativeVideoCapture.create(
        deviceId: deviceId, width: width, height: height, fps: framerate);
    if (cap == null) return null;
    if (!cap.start()) {
      cap.release();
      return null;
    }
    // Half the frame period leaves room for jitter without piling up.
    final interval = Duration(
        microseconds:
            ((1000000 / framerate) / 2).round().clamp(2000, 33000));
    return AvfCaptureVideoTrack._(
        cap, Csprng.randomHex(16), label, interval);
  }

  @override
  String get kind => 'video';

  @override
  Stream<VideoFrame> get onVideoFrame => _events.stream;

  @override
  Stream<AudioData> get onAudioData =>
      throw UnsupportedError('Video track does not produce audio data');

  @override
  bool _drainOne() {
    final frame = _capture.popFrame();
    if (frame == null) return false;
    if (_enabled) {
      _events.add(VideoFrame(
        format: VideoPixelFormat.i420,
        codedWidth: frame.width,
        codedHeight: frame.height,
        timestamp: frame.ptsUs,
        data: frame.data,
      ));
    }
    return true;
  }

  @override
  void _disposeNativeCapture() {
    _capture.stop();
    _capture.release();
  }
}

/// Microphone-backed audio track. Drains the native s16-interleaved PCM
/// queue and emits [AudioData] on [onAudioData].
final class AvfCaptureAudioTrack extends _AvfCaptureTrack<AudioData> {
  final NativeAudioCapture _capture;

  AvfCaptureAudioTrack._(this._capture, String id, String label)
      : super(id, label, const Duration(milliseconds: 10));

  static AvfCaptureAudioTrack? create({
    String? deviceId,
    String label = 'microphone',
    int sampleRate = 48000,
    int channels = 1,
  }) {
    final cap = NativeAudioCapture.create(
        deviceId: deviceId, sampleRate: sampleRate, channels: channels);
    if (cap == null) return null;
    if (!cap.start()) {
      cap.release();
      return null;
    }
    return AvfCaptureAudioTrack._(cap, Csprng.randomHex(16), label);
  }

  @override
  String get kind => 'audio';

  @override
  Stream<AudioData> get onAudioData => _events.stream;

  @override
  Stream<VideoFrame> get onVideoFrame =>
      throw UnsupportedError('Audio track does not produce video frames');

  @override
  bool _drainOne() {
    final frame = _capture.popFrame();
    if (frame == null) return false;
    // W3C: when disabled, audio tracks emit silent frames (not gaps) so
    // downstream packetisers keep their cadence.
    final data = _enabled ? frame.data : Uint8List(frame.data.length);
    _events.add(AudioData(
      format: AudioSampleFormat.s16,
      sampleRate: frame.sampleRate,
      numberOfChannels: frame.channels,
      numberOfFrames: frame.numFrames,
      timestamp: frame.ptsUs,
      data: data,
    ));
    return true;
  }

  @override
  void _disposeNativeCapture() {
    _capture.stop();
    _capture.release();
  }
}
