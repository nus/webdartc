/// Pure-Dart `getUserMedia` demo on macOS.
///
/// Enumerates AVFoundation devices, opens the default camera at 640×480/30
/// and the default microphone at 48 kHz, and prints one summary line per
/// received frame for ten seconds.
///
/// Usage:
///   dart run example/get_user_media_macos.dart
///
/// The first run triggers the macOS TCC prompts for camera and microphone
/// access; subsequent runs reuse the cached decision.
import 'dart:async';
import 'dart:io';

import 'package:webdartc/media/macos/avf_media_devices.dart';
import 'package:webdartc/webdartc.dart';

Future<void> main() async {
  if (!Platform.isMacOS) {
    stderr.writeln('This example only runs on macOS.');
    exit(64);
  }

  registerAvfMediaDevicesBackend();

  print('--- enumerateDevices ---');
  final devices = await MediaDevices.enumerateDevices();
  for (final d in devices) {
    print('  [${d.kind}] ${d.label}  (${d.deviceId})');
  }

  print('\n--- getUserMedia(video+audio) ---');
  final stream = await MediaDevices.getUserMedia(MediaStreamConstraints(
    video: const MediaTrackConstraints(
      width: 640,
      height: 480,
      frameRate: 30,
    ),
    audio: const MediaTrackConstraints(
      sampleRate: 48000,
      channelCount: 1,
    ),
  ));

  for (final t in stream.getTracks()) {
    print('  ${t.kind} track: ${t.label} (id=${t.id})');
  }

  var videoFrames = 0;
  var audioFrames = 0;
  final video = stream.getVideoTracks().firstOrNull;
  final audio = stream.getAudioTracks().firstOrNull;
  final subs = <StreamSubscription<void>>[];
  if (video != null) {
    subs.add(video.onVideoFrame.listen((f) {
      videoFrames++;
      if (videoFrames % 30 == 0) {
        print('  [video] ${f.codedWidth}x${f.codedHeight} '
            'pts=${f.timestamp}us total=$videoFrames');
      }
    }));
  }
  if (audio != null) {
    subs.add(audio.onAudioData.listen((d) {
      audioFrames++;
      if (audioFrames % 100 == 0) {
        print('  [audio] ${d.numberOfFrames} samples @ ${d.sampleRate}Hz '
            'ch=${d.numberOfChannels} total=$audioFrames');
      }
    }));
  }

  await Future<void>.delayed(const Duration(seconds: 10));

  for (final s in subs) {
    await s.cancel();
  }
  for (final t in stream.getTracks()) {
    t.stop();
  }
  print('\nstopped: video=$videoFrames frames, audio=$audioFrames packets');
}
