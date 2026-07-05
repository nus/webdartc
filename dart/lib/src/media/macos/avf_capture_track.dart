/// MediaStreamTrack subclasses backed by AVFoundation capture.
///
/// Each track polls its native FIFO queue on a timer (≈ half the frame
/// interval for video, 10 ms for audio so 20-ms PCM packets stay near
/// real-time). Polling avoids `Dart_PostCObject_DL` and keeps the
/// foreign-thread surface inside the C shim.
library;

import 'dart:async';

import '../../crypto/csprng.dart';
import '../audio_data.dart';
import '../media_stream_track.dart';
import '../video_frame.dart';
import 'avf_media.dart';

abstract base class _AvfCaptureTrack<TEvent> extends StreamBackedTrack<TEvent> {
  final Duration _pollInterval;
  final MediaTrackSettings _settings;
  Timer? _timer;

  _AvfCaptureTrack(
      String id, String label, this._pollInterval, this._settings)
      : super(id: id, label: label);

  @override
  MediaTrackSettings getSettings() => _settings;

  /// Pop and emit a single native frame. Returns false when the queue is
  /// empty so the drain loop can stop.
  bool _drainOne();

  /// Stop and release the underlying native capture.
  void _disposeNativeCapture();

  @override
  MediaStreamTrack clone() =>
      throw UnsupportedError('AvfCaptureTrack.clone is not implemented');

  // Polling starts when a listener attaches and ends when the last one
  // detaches.
  @override
  void onFirstListener() {
    _timer ??= Timer.periodic(_pollInterval, (_) => _drain());
  }

  @override
  void onLastListenerGone() {
    _timer?.cancel();
    _timer = null;
  }

  @override
  void onStop() {
    _timer?.cancel();
    _timer = null;
    _disposeNativeCapture();
  }

  void _drain() {
    if (events.isClosed) return;
    while (_drainOne()) {}
  }
}

/// Camera-backed video track. Drains the native I420 queue and emits
/// [VideoFrame]s on [onVideoFrame].
final class AvfCaptureVideoTrack extends _AvfCaptureTrack<VideoFrame> {
  final NativeVideoCapture _capture;

  AvfCaptureVideoTrack._(
      this._capture, super.id, super.label, super.interval, super.settings);

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
        cap, Csprng.randomHex(16), label, interval,
        MediaTrackSettings(
            deviceId: deviceId,
            width: width,
            height: height,
            frameRate: framerate));
  }

  @override
  String get kind => 'video';

  @override
  Stream<VideoFrame> get onVideoFrame => events.stream;

  @override
  Stream<AudioData> get onAudioData =>
      throw UnsupportedError('Video track does not produce audio data');

  @override
  bool _drainOne() {
    final frame = _capture.popFrame();
    if (frame == null) return false;
    if (enabled) {
      events.add(VideoFrame(
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

  AvfCaptureAudioTrack._(
      this._capture, String id, String label, MediaTrackSettings settings)
      : super(id, label, const Duration(milliseconds: 10), settings);

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
    return AvfCaptureAudioTrack._(cap, Csprng.randomHex(16), label,
        MediaTrackSettings(
            deviceId: deviceId,
            sampleRate: sampleRate,
            channelCount: channels));
  }

  @override
  String get kind => 'audio';

  @override
  Stream<AudioData> get onAudioData => events.stream;

  @override
  Stream<VideoFrame> get onVideoFrame =>
      throw UnsupportedError('Audio track does not produce video frames');

  @override
  bool _drainOne() {
    final frame = _capture.popFrame();
    if (frame == null) return false;
    final audio = AudioData(
      format: AudioSampleFormat.s16,
      sampleRate: frame.sampleRate,
      numberOfChannels: frame.channels,
      numberOfFrames: frame.numFrames,
      timestamp: frame.ptsUs,
      data: frame.data,
    );
    // W3C: when disabled, audio tracks emit silent frames (not gaps) so
    // downstream packetisers keep their cadence.
    events.add(enabled ? audio : AudioData.silenceLike(audio));
    return true;
  }

  @override
  void _disposeNativeCapture() {
    _capture.stop();
    _capture.release();
  }
}
