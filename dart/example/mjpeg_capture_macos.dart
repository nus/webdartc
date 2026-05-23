/// MJPEG passthrough capture + RFC 2435 packetize/depacketize round-trip.
///
/// Opens the default camera in MJPEG passthrough mode (no I420 conversion,
/// no re-encoding on the sender), feeds each frame through
/// [JpegPacketizer] → [JpegDepacketizer], and writes the first ten
/// reassembled JPEGs to `./mjpeg_out/frame_NN.jpg` so you can confirm
/// they're decodable in any image viewer.
///
/// Use this as a starting point for full sender + receiver wiring against
/// `PeerConnection.addTransceiver('video', preferredCodecs: ['JPEG'])`
/// with `MediaEngine(videoCodecs: [MediaEngine.jpegVideoCodec, ...])`.
///
/// Usage:
///   dart run example/mjpeg_capture_macos.dart \
///       [--device=<id>] [--width=1280] [--height=720] [--fps=30] \
///       [--frames=10]
///
/// Requires an MJPEG-capable camera. macOS built-in FaceTime cameras only
/// expose uncompressed formats — the demo exits with an error in that
/// case. Most external USB UVC webcams advertise MJPEG.
library;

import 'dart:async';
import 'dart:io';

import 'package:webdartc/media/macos/avf_capture.dart';
import 'package:webdartc/media/macos/avf_capture_track.dart';
import 'package:webdartc/rtp/packetizer.dart';

Future<void> main(List<String> args) async {
  if (!Platform.isMacOS) {
    stderr.writeln('This example only runs on macOS.');
    exit(64);
  }

  String? deviceId;
  var width = 1280;
  var height = 720;
  var fps = 30.0;
  var totalFrames = 10;
  for (final a in args) {
    if (a.startsWith('--device=')) deviceId = a.substring(9);
    if (a.startsWith('--width=')) width = int.parse(a.substring(8));
    if (a.startsWith('--height=')) height = int.parse(a.substring(9));
    if (a.startsWith('--fps=')) fps = double.parse(a.substring(6));
    if (a.startsWith('--frames=')) totalFrames = int.parse(a.substring(9));
  }

  if (!requestVideoAccessBlocking()) {
    stderr.writeln('Camera access denied.');
    exit(1);
  }

  final track = AvfCaptureMjpegTrack.create(
    deviceId: deviceId,
    width: width,
    height: height,
    framerate: fps,
  );
  if (track == null) {
    stderr.writeln(
        'No MJPEG-capable format on the requested camera. Try --device=<id> '
        'pointing at an external UVC camera, or relax --width/--height/--fps.');
    exit(2);
  }

  final outDir = Directory('mjpeg_out');
  await outDir.create(recursive: true);

  final packetizer = JpegPacketizer();
  final depacketizer = JpegDepacketizer();

  var rtpTs = 0;
  var emitted = 0;
  final done = Completer<void>();

  final sub = track.onEncodedChunk.listen((chunk) {
    if (emitted >= totalFrames) return;
    // Advance the RTP timestamp by one frame interval at 90 kHz so each
    // frame depacketizes with a distinct timestamp.
    rtpTs = (rtpTs + (90000 ~/ fps.round())) & 0xFFFFFFFF;

    final parts = packetizer.packetize(chunk.data, isKeyFrame: true);
    for (final (payload, marker) in parts) {
      final out = depacketizer.depacketize(
          payload, marker: marker, timestamp: rtpTs);
      if (out == null) continue;
      final idx = emitted.toString().padLeft(2, '0');
      final file = File('${outDir.path}/frame_$idx.jpg');
      file.writeAsBytesSync(out.data);
      stdout.writeln('wrote ${file.path} '
          '(${chunk.data.length}B in → ${parts.length} pkts → '
          '${out.data.length}B out)');
      emitted++;
      if (emitted >= totalFrames) done.complete();
    }
  });

  await done.future.timeout(const Duration(seconds: 10),
      onTimeout: () => stderr.writeln('timed out waiting for $totalFrames '
          'frames (got $emitted)'));
  await sub.cancel();
  track.stop();
  stdout.writeln('done — open ${outDir.path}/ to view the JPEGs.');
}
