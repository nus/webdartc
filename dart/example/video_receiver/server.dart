/// webdartc video-receiver example — receives a browser camera stream
/// (VP8 or H.264 / SRTP / DTLS / ICE) using the W3C receive path:
/// `onTrack` → `track.onVideoFrame` yields decoded frames. The jitter
/// buffer, depacketiser (RFC 7741 / RFC 6184) and decoder (libvpx for
/// VP8, VideoToolbox or OpenH264 for H.264) all live inside the track —
/// no manual RTP plumbing required.
///
/// HTTP + WebSocket + Dart peer in one binary. The browser is the
/// offerer: it captures `getUserMedia({video:true})`, adds the track,
/// and creates an offer. Dart answers with `recvonly` and starts
/// decoding.
///
/// Usage:
///   dart run example/video_receiver/server.dart \
///     [--port=8080] [--codec=vp8|h264]
///
/// Then open `http://127.0.0.1:<port>` in Chrome and grant camera
/// permission. On macOS the H.264 path uses VideoToolbox.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/webdartc.dart';

import '../serve.dart';

int _port = 8080;
String _codec = 'vp8';

Future<void> main(List<String> args) async {
  for (final a in args) {
    if (a.startsWith('--port=')) _port = int.parse(a.substring(7));
    if (a.startsWith('--codec=')) _codec = a.substring(8).toLowerCase();
  }
  if (_codec != 'vp8' && _codec != 'h264') {
    stderr.writeln('Unsupported codec: $_codec (expected vp8 or h264)');
    exit(2);
  }
  // Codec backends are auto-registered by PeerConnection, so the W3C receive
  // path decodes out of the box — no registerVp8Codec()/registerH264Codec().

  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  print(
      '[video_receiver] listening on http://127.0.0.1:$_port (codec=$_codec)');
  print('[video_receiver] open the URL above in Chrome (camera permission required)');

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
  print('[video_receiver] WS client connected');

  PeerConnection? pc;

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type']) {
        case 'offer':
          print('[video_receiver] received offer');
          pc = PeerConnection(
              configuration: const PeerConnectionConfiguration());
          pc!.addTransceiver(
            'video',
            direction: 'recvonly',
            preferredCodecs: [_codec.toUpperCase()],
          );

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
              .listen((s) => print('[video_receiver] ICE: $s'));
          pc!.onConnectionStateChange
              .listen((s) => print('[video_receiver] PC: $s'));
          pc!.onTrack.listen((evt) {
            if (evt.kind != 'video') return;
            print(
                '[video_receiver] onTrack kind=${evt.kind} ssrc=${evt.ssrc}');
            final track = evt.track;
            if (track == null) {
              print('[video_receiver] no decoder available for this codec');
              return;
            }
            // Subscribing starts the jitter→depacketize→decode pipeline.
            var decoded = 0;
            track.onVideoFrame.listen((frame) {
              decoded++;
              if (decoded <= 3 || decoded % 30 == 0) {
                print('[video_receiver] decoded #$decoded '
                    '${frame.codedWidth}x${frame.codedHeight} '
                    'ts=${frame.timestamp}');
              }
              frame.close();
            });
          });

          await pc!.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: msg['sdp'] as String,
          ));
          final answer = await pc!.createAnswer();
          await pc!.setLocalDescription(answer);
          ws.add(jsonEncode({'type': 'answer', 'sdp': answer.sdp}));
          print('[video_receiver] sent answer');

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
      print('[video_receiver] WS client disconnected');
      await pc?.close();
    },
    onError: (_) async => await pc?.close(),
  );
}
