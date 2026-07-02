/// webdartc video-sender example — streams a FakeVideoSource (rolling
/// millisecond timestamps on a grey background) to a browser over VP8,
/// VP9 or H.264 / SRTP / DTLS / ICE.
///
/// HTTP + WebSocket + Dart peer in one binary. The browser is the
/// offerer: it opens the WebSocket, declares a `recvonly` video
/// transceiver, and creates an offer. Dart answers with `sendonly` and
/// starts encoding once the connection is established.
///
/// Usage:
///   dart run example/video_sender/server.dart \
///     [--port=8080] [--codec=vp8|vp9|h264]
///
/// Then open `http://127.0.0.1:<port>` in Chrome.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/rtp/packetizer.dart';
import 'package:webdartc/webdartc.dart';

import '../serve.dart';

int _port = 8080;
String _codec = 'vp8';

Future<void> main(List<String> args) async {
  for (final a in args) {
    if (a.startsWith('--port=')) _port = int.parse(a.substring(7));
    if (a.startsWith('--codec=')) _codec = a.substring(8).toLowerCase();
  }
  if (_codec != 'vp8' && _codec != 'vp9' && _codec != 'h264') {
    stderr.writeln('Unsupported codec: $_codec (expected vp8, vp9 or h264)');
    exit(2);
  }
  switch (_codec) {
    case 'vp8':
      registerVp8Codec();
    case 'vp9':
      registerVp9Codec();
    case 'h264':
      registerH264Codec();
  }

  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  print(
      '[video_sender] listening on http://127.0.0.1:$_port (codec=$_codec)');
  print('[video_sender] open the URL above in Chrome to start');

  await for (final req in server) {
    if (WebSocketTransformer.isUpgradeRequest(req)) {
      final ws = await WebSocketTransformer.upgrade(req);
      unawaited(_handleWs(ws));
    } else {
      await serveExampleStatic(req);
    }
  }
}

Future<void> _handleWs(WebSocket ws) async {
  print('[video_sender] WS client connected');

  PeerConnection? pc;
  VideoEncoder? encoder;
  StreamSubscription<VideoFrame>? frameSub;

  Future<void> teardown() async {
    await frameSub?.cancel();
    encoder?.close();
    await pc?.close();
  }

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type']) {
        case 'offer':
          print('[video_sender] received offer');
          pc = PeerConnection(
              configuration: const PeerConnectionConfiguration());
          pc!.addTransceiver(
            'video',
            direction: 'sendonly',
            preferredCodecs: [_codec.toUpperCase()],
          );
          final sender = pc!.getSenders().firstWhere((s) => s.kind == 'video');

          pc!.onIceCandidate.listen((evt) {
            ws.add(jsonEncode({
              'type': 'candidate',
              'candidate': {
                'candidate': evt.candidate,
                'sdpMid': evt.sdpMid,
                'sdpMLineIndex': evt.sdpMLineIndex,
              }
            }));
          });
          pc!.onIceConnectionStateChange
              .listen((s) => print('[video_sender] ICE: $s'));
          pc!.onConnectionStateChange.listen((s) {
            print('[video_sender] PC: $s');
            if (s == PeerConnectionState.connected) {
              final stream = _startVideoStream(sender);
              encoder = stream.encoder;
              frameSub = stream.sub;
            }
          });

          await pc!.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: msg['sdp'] as String,
          ));
          final answer = await pc!.createAnswer();
          await pc!.setLocalDescription(answer);
          ws.add(jsonEncode({'type': 'answer', 'sdp': answer.sdp}));
          print('[video_sender] sent answer');

        case 'candidate':
          final c = msg['candidate'];
          if (c is Map<String, dynamic> && pc != null) {
            await pc!.addIceCandidate(IceCandidateInit(
              candidate: (c['candidate'] as String?) ?? '',
              sdpMid: (c['sdpMid'] as String?) ?? '0',
              sdpMLineIndex: (c['sdpMLineIndex'] as int?) ?? 0,
            ));
          }
      }
    },
    onDone: () async {
      print('[video_sender] WS client disconnected');
      await teardown();
    },
    onError: (_) async => teardown(),
  );
}

({VideoEncoder encoder, StreamSubscription<VideoFrame> sub}) _startVideoStream(
    RtpSender sender) {
  const width = 320, height = 240, framerate = 30;
  final packetizer = videoPacketizerFor(_codec)!;
  final encoder = VideoEncoder(
    output: (chunk, _) {
      final rtpTs = (chunk.timestamp * 90) ~/ 1000;
      final parts = packetizer.packetize(
        chunk.data,
        isKeyFrame: chunk.type == EncodedVideoChunkType.key,
      );
      for (final (payload, marker) in parts) {
        sender.sendRtp(payload, marker: marker, timestamp: rtpTs);
      }
    },
    error: (e) => stderr.writeln('[video_sender] encoder error: $e'),
  );
  encoder.configure(VideoEncoderConfig(
    codec: _codec,
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
  return (encoder: encoder, sub: sub);
}
