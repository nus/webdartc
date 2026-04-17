/// Dart sender that sends a fake video stream to the browser client
/// running at the signaling server's URL.
///
/// Usage:
///   dart run example/video_call/bin/sender.dart \
///     [--port=8080] [--codec=vp8|h264]
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/rtp/packetizer.dart';
import 'package:webdartc/webdartc.dart';

Future<void> main(List<String> args) async {
  var port = 8080;
  var codec = 'vp8';
  for (final a in args) {
    if (a.startsWith('--port=')) port = int.parse(a.substring(7));
    if (a.startsWith('--codec=')) codec = a.substring(8).toLowerCase();
  }
  if (codec != 'vp8' && codec != 'h264') {
    stderr.writeln('Unsupported codec: $codec (expected vp8 or h264)');
    exit(2);
  }

  // Register the chosen codec's backend.
  switch (codec) {
    case 'vp8':
      registerVp8Codec();
    case 'h264':
      registerH264Codec();
  }

  final ws = await WebSocket.connect('ws://127.0.0.1:$port');
  stdout.writeln('[sender] signaling connected (codec=$codec)');

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
  pc.addTransceiver(
    'video',
    direction: 'sendonly',
    preferredCodecs: [codec.toUpperCase()],
  );
  final sender = pc.getSenders().firstWhere((s) => s.kind == 'video');

  pc.onIceCandidate.listen((evt) {
    ws.add(jsonEncode({
      'type': 'candidate',
      'candidate': {
        'candidate': evt.candidate,
        'sdpMid': evt.sdpMid,
        'sdpMLineIndex': evt.sdpMLineIndex,
      }
    }));
  });

  pc.onIceConnectionStateChange
      .listen((s) => stdout.writeln('[sender] ICE: $s'));
  pc.onConnectionStateChange
      .listen((s) => stdout.writeln('[sender] PC: $s'));

  ws.listen((data) async {
    if (data is! String) return;
    final msg = jsonDecode(data) as Map<String, dynamic>;
    switch (msg['type'] as String?) {
      case 'answer':
        await pc.setRemoteDescription(SessionDescription(
          type: SessionDescriptionType.answer,
          sdp: msg['sdp'] as String,
        ));
      case 'candidate':
        final c = msg['candidate'];
        if (c is Map<String, dynamic>) {
          await pc.addIceCandidate(IceCandidateInit(
            candidate: (c['candidate'] as String?) ?? '',
            sdpMid: (c['sdpMid'] as String?) ?? '0',
            sdpMLineIndex: (c['sdpMLineIndex'] as int?) ?? 0,
          ));
        }
    }
  });

  final offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  ws.add(jsonEncode({'type': 'offer', 'sdp': offer.sdp}));

  await pc.onConnectionStateChange
      .firstWhere((s) => s == PeerConnectionState.connected)
      .timeout(const Duration(seconds: 30));
  stdout.writeln('[sender] connected — starting video');

  const width = 320, height = 240, framerate = 30;
  final PayloadPacketizer packetizer =
      codec == 'h264' ? H264Packetizer() : Vp8Packetizer();
  final encoder = VideoEncoder(
    output: (chunk, _) {
      final rtpTs = (chunk.timestamp * 90) ~/ 1000; // us → 90 kHz
      final parts = packetizer.packetize(
        chunk.data,
        isKeyFrame: chunk.type == EncodedVideoChunkType.key,
      );
      for (final (payload, marker) in parts) {
        sender.sendRtp(payload, marker: marker, timestamp: rtpTs);
      }
    },
    error: (e) => stderr.writeln('[sender] encoder error: $e'),
  );
  encoder.configure(VideoEncoderConfig(
    codec: codec,
    width: width,
    height: height,
    bitrate: 400000,
    framerate: framerate.toDouble(),
    latencyMode: 'realtime',
  ));

  final source = FakeVideoSource(
      width: width, height: height, framerate: framerate.toDouble());
  var frameCount = 0;
  final sub = source.start().listen((frame) {
    encoder.encode(frame, VideoEncoderEncodeOptions(keyFrame: frameCount == 0));
    frame.close();
    frameCount++;
  });

  ProcessSignal.sigint.watch().listen((_) async {
    stdout.writeln('[sender] shutting down');
    await sub.cancel();
    encoder.close();
    await pc.close();
    await ws.close();
    exit(0);
  });
}
