/// Speaker output demo on macOS.
///
/// Enumerates available output devices (kind == 'audiooutput'), then
/// plays a 1-second 440 Hz sine tone through the AudioRenderer. Each
/// device gets a tone — pass `--device=<deviceId>` to play through a
/// specific one instead of every device in turn.
///
/// Usage:
///   dart run example/audio_renderer_macos.dart
///   dart run example/audio_renderer_macos.dart --device=BuiltInSpeakerDevice
import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:webdartc/media/macos/avf_audio_renderer.dart';
import 'package:webdartc/media/macos/avf_media_devices.dart';
import 'package:webdartc/webdartc.dart';

Future<void> main(List<String> args) async {
  if (!Platform.isMacOS) {
    stderr.writeln('This example only runs on macOS.');
    exit(64);
  }

  String? onlyDevice;
  for (final a in args) {
    if (a.startsWith('--device=')) onlyDevice = a.substring(9);
  }

  registerAvfMediaDevicesBackend();

  final devices = await MediaDevices.enumerateDevices();
  final outputs = devices.where((d) => d.kind == 'audiooutput').toList();
  print('--- audiooutput devices ---');
  for (final d in outputs) {
    print('  ${d.label}  (${d.deviceId})');
  }
  if (outputs.isEmpty) {
    stderr.writeln('No audio output devices found.');
    exit(1);
  }

  final renderer = AudioRenderer(sampleRate: 48000, channels: 1);

  final targets = onlyDevice == null
      ? outputs
      : outputs.where((d) => d.deviceId == onlyDevice).toList();
  if (targets.isEmpty) {
    stderr.writeln('Device id "$onlyDevice" not found.');
    exit(2);
  }

  try {
    for (final d in targets) {
      print('\nplaying 440 Hz / 1 s through ${d.label}');
      await renderer.setSinkId(d.deviceId);
      await _playTone(renderer,
          frequency: 440, durationMs: 1000, sampleRate: 48000);
    }
  } finally {
    renderer.close();
  }
}

Future<void> _playTone(
  AudioRenderer renderer, {
  required double frequency,
  required int durationMs,
  required int sampleRate,
}) async {
  const chunkMs = 20;
  final samplesPerChunk = (sampleRate * chunkMs) ~/ 1000;
  final chunks = durationMs ~/ chunkMs;
  var phase = 0.0;
  final dPhase = 2 * math.pi * frequency / sampleRate;

  // Pace to wall-clock so the producer matches the playback rate — over-
  // producing would overflow the renderer's bounded ring and silently
  // drop chunks.
  final start = DateTime.now();
  for (var i = 0; i < chunks; i++) {
    final buf = Uint8List(samplesPerChunk * 2);
    final view = ByteData.view(buf.buffer);
    for (var n = 0; n < samplesPerChunk; n++) {
      final sample = (math.sin(phase) * 0.3 * 32767).toInt();
      view.setInt16(n * 2, sample, Endian.little);
      phase += dPhase;
    }
    renderer.push(AudioData(
      format: AudioSampleFormat.s16,
      sampleRate: sampleRate,
      numberOfChannels: 1,
      numberOfFrames: samplesPerChunk,
      timestamp: i * chunkMs * 1000,
      data: buf,
    ));
    final due = start.add(Duration(milliseconds: (i + 1) * chunkMs));
    final lag = due.difference(DateTime.now());
    if (lag.inMicroseconds > 0) await Future<void>.delayed(lag);
  }
  // Let the queued audio actually play out before returning.
  await Future<void>.delayed(Duration(milliseconds: chunkMs * 4));
}
