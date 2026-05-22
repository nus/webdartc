/// AVFoundation-backed [MediaDevicesBackend] for macOS and iOS.
library;

import 'dart:io' show Platform;

import '../media_devices.dart';
import '../media_stream.dart';
import 'avf_capture.dart';
import 'avf_capture_track.dart';

final class AvfMediaDevicesBackend implements MediaDevicesBackend {
  /// When true, [getUserMedia] blocks on the system TCC prompt the first
  /// time it's called (browser-equivalent semantics). Set false for
  /// scripted tests where blocking is undesirable.
  final bool requestAccessOnDemand;

  const AvfMediaDevicesBackend({this.requestAccessOnDemand = true});

  @override
  Future<List<MediaDeviceInfo>> enumerateDevices() async {
    final video = enumerateDevicesNative(WmdDeviceKind.video);
    final audio = enumerateDevicesNative(WmdDeviceKind.audio);
    return [
      for (final d in video)
        MediaDeviceInfo(deviceId: d.id, kind: 'videoinput', label: d.label),
      for (final d in audio)
        MediaDeviceInfo(deviceId: d.id, kind: 'audioinput', label: d.label),
    ];
  }

  @override
  Future<MediaStream> getUserMedia(MediaStreamConstraints constraints) async {
    if (!constraints.hasAudio && !constraints.hasVideo) {
      throw ArgumentError(
          'getUserMedia requires at least one of audio or video');
    }

    final stream = MediaStream();

    if (constraints.hasVideo) {
      if (requestAccessOnDemand && !requestVideoAccessBlocking()) {
        throw StateError('Camera access denied');
      }
      final c = _asTrackConstraints(constraints.video);
      final track = AvfCaptureVideoTrack.create(
        deviceId: c?.deviceId,
        width: c?.width ?? 1280,
        height: c?.height ?? 720,
        framerate: c?.frameRate ?? 30,
      );
      if (track == null) {
        throw StateError('Failed to start video capture');
      }
      stream.addTrack(track);
    }

    if (constraints.hasAudio) {
      if (requestAccessOnDemand && !requestAudioAccessBlocking()) {
        // Roll back any already-started video track so callers never see
        // a half-open stream after a permission denial.
        for (final t in stream.getTracks()) {
          t.stop();
        }
        throw StateError('Microphone access denied');
      }
      final c = _asTrackConstraints(constraints.audio);
      final track = AvfCaptureAudioTrack.create(
        deviceId: c?.deviceId,
        sampleRate: c?.sampleRate ?? 48000,
        channels: c?.channelCount ?? 1,
      );
      if (track == null) {
        for (final t in stream.getTracks()) {
          t.stop();
        }
        throw StateError('Failed to start audio capture');
      }
      stream.addTrack(track);
    }

    return stream;
  }

  static MediaTrackConstraints? _asTrackConstraints(Object? raw) {
    if (raw is MediaTrackConstraints) return raw;
    return null;
  }
}

void registerAvfMediaDevicesBackend({bool requestAccessOnDemand = true}) {
  if (!Platform.isMacOS && !Platform.isIOS) {
    throw UnsupportedError(
        'AvfMediaDevicesBackend is only available on macOS and iOS '
        '(current platform: ${Platform.operatingSystem})');
  }
  MediaDevices.registerBackend(
      AvfMediaDevicesBackend(requestAccessOnDemand: requestAccessOnDemand));
}
