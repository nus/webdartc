/// W3C MediaDevices — access to capture devices.
/// https://www.w3.org/TR/mediacapture-streams/#mediadevices
library;

import 'media_stream.dart';

/// Constraints for getUserMedia().
final class MediaTrackConstraints {
  final int? width;
  final int? height;
  final double? frameRate;
  final int? sampleRate;
  final int? channelCount;
  final String? deviceId;

  const MediaTrackConstraints({
    this.width,
    this.height,
    this.frameRate,
    this.sampleRate,
    this.channelCount,
    this.deviceId,
  });
}

/// Constraints passed to getUserMedia().
final class MediaStreamConstraints {
  /// true, false, or MediaTrackConstraints for audio.
  final Object? audio; // bool or MediaTrackConstraints
  /// true, false, or MediaTrackConstraints for video.
  final Object? video; // bool or MediaTrackConstraints

  const MediaStreamConstraints({this.audio, this.video});

  bool get hasAudio => audio == true || audio is MediaTrackConstraints;
  bool get hasVideo => video == true || video is MediaTrackConstraints;
}

/// Information about a media device.
final class MediaDeviceInfo {
  final String deviceId;
  final String kind; // 'audioinput', 'videoinput', 'audiooutput'
  final String label;

  const MediaDeviceInfo({
    required this.deviceId,
    required this.kind,
    required this.label,
  });
}

/// Platform-specific capture backend.
///
/// Implementors provide this interface using FFI to platform capture APIs
/// (e.g. AVFoundation on macOS, V4L2 + PulseAudio on Linux).
abstract interface class MediaDevicesBackend {
  Future<MediaStream> getUserMedia(MediaStreamConstraints constraints);
  Future<List<MediaDeviceInfo>> enumerateDevices();
}

/// Top-level media device access — register a backend before use.
///
/// Example:
/// ```dart
/// MediaDevices.registerBackend(MyAVFoundationBackend());
/// final stream = await MediaDevices.getUserMedia(
///   MediaStreamConstraints(audio: true, video: true),
/// );
/// ```
abstract final class MediaDevices {
  static MediaDevicesBackend? _backend;

  static void registerBackend(MediaDevicesBackend backend) {
    _backend = backend;
  }

  static Future<MediaStream> getUserMedia(MediaStreamConstraints constraints) {
    final b = _backend;
    if (b == null) {
      throw UnsupportedError(
          'No MediaDevices backend registered. '
          'Call MediaDevices.registerBackend() first.');
    }
    return b.getUserMedia(constraints);
  }

  static Future<List<MediaDeviceInfo>> enumerateDevices() {
    final b = _backend;
    if (b == null) {
      throw UnsupportedError(
          'No MediaDevices backend registered. '
          'Call MediaDevices.registerBackend() first.');
    }
    return b.enumerateDevices();
  }
}
