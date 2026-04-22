/// Dart sender for the video_call sample.
///
/// By default sends a fake video stream to the browser (sendonly). With
/// `--bidir`, also subscribes to the browser's track and decodes it — used
/// to exercise the Dart receive/decode path (e.g. VideoToolbox H.264
/// decoder on macOS).
///
/// Usage:
///   dart run example/video_call/bin/sender.dart \
///     [--port=8080] [--codec=vp8|h264] [--bidir]
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/rtp/packetizer.dart';
import 'package:webdartc/webdartc.dart';

Future<void> main(List<String> args) async {
  var port = 8080;
  var codec = 'vp8';
  var bidir = false;
  for (final a in args) {
    if (a.startsWith('--port=')) port = int.parse(a.substring(7));
    if (a.startsWith('--codec=')) codec = a.substring(8).toLowerCase();
    if (a == '--bidir') bidir = true;
  }
  if (codec != 'vp8' && codec != 'h264') {
    stderr.writeln('Unsupported codec: $codec (expected vp8 or h264)');
    exit(2);
  }

  // Register the chosen codec's backend (encoder on all platforms;
  // decoder on macOS/iOS where VideoToolbox is wired).
  switch (codec) {
    case 'vp8':
      registerVp8Codec();
    case 'h264':
      registerH264Codec();
  }

  final ws = await WebSocket.connect('ws://127.0.0.1:$port');
  stdout.writeln('[sender] signaling connected (codec=$codec, bidir=$bidir)');

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
  pc.addTransceiver(
    'video',
    direction: bidir ? 'sendrecv' : 'sendonly',
    preferredCodecs: [codec.toUpperCase()],
  );
  final sender = pc.getSenders().firstWhere((s) => s.kind == 'video');

  if (bidir) {
    pc.onTrack.listen((evt) {
      if (evt.kind != 'video') return;
      stdout.writeln(
          '[sender] onTrack kind=${evt.kind} ssrc=${evt.ssrc} — '
          'starting depacketizer + decoder');
      _pipeIncoming(evt.receiver, codec);
    });
  }

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

void _pipeIncoming(RtpReceiver receiver, String codec) {
  final VideoPayloadDepacketizer depack =
      codec == 'h264' ? H264Depacketizer() : Vp8Depacketizer();
  var decoded = 0;
  var decoderConfigured = false;
  final decoder = VideoDecoder(
    output: (frame) {
      decoded++;
      if (decoded <= 3 || decoded % 30 == 0) {
        stdout.writeln('[sender] decoded #$decoded '
            '${frame.codedWidth}x${frame.codedHeight} '
            'ts=${frame.timestamp}');
      }
      frame.close();
    },
    error: (e) => stderr.writeln('[sender] decoder error: $e'),
  );

  receiver.onRtp.listen((rtp) {
    final chunk = depack.depacketize(
      rtp.payload,
      marker: rtp.marker,
      timestamp: rtp.timestamp,
    );
    if (chunk == null) return;
    if (!decoderConfigured) {
      // Wait for the first keyframe so H.264 decoder has SPS/PPS in hand
      // (or VP8 decoder has a reference frame).
      if (chunk.type != EncodedVideoChunkType.key) return;
      decoder.configure(VideoDecoderConfig(codec: codec));
      decoderConfigured = true;
    }
    decoder.decode(chunk);
  });
}
