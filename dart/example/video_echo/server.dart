/// webdartc video-echo example — reflects every received RTP packet
/// back to the browser via the matching sender. The browser sees its
/// own camera feed echoed after a round-trip through the Dart peer.
///
/// HTTP + WebSocket + Dart peer in one binary. The browser is the
/// offerer: it captures `getUserMedia({video:true})`, adds the track
/// and creates an offer. Dart answers with `sendrecv` and forwards
/// RTP via the W3C RTP Transport API (`replacePacketReceiver` /
/// `replacePacketSender`) — no encoder or decoder on the Dart side.
///
/// Usage:
///   dart run example/video_echo/server.dart [--port=8080]
///
/// Then open `http://127.0.0.1:<port>` in Chrome (camera permission
/// required). The `local` tile shows the camera feed; the `remote`
/// tile shows the same feed after the Dart round-trip.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/webdartc.dart';

import '../serve.dart';

int _port = 8080;

Future<void> main(List<String> args) async {
  for (final a in args) {
    if (a.startsWith('--port=')) _port = int.parse(a.substring(7));
  }

  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  print('[video_echo] listening on http://127.0.0.1:$_port');
  print('[video_echo] open the URL above in Chrome (camera permission required)');

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
  print('[video_echo] WS client connected');

  PeerConnection? pc;

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type']) {
        case 'offer':
          print('[video_echo] received offer');
          pc = PeerConnection(
              configuration: const PeerConnectionConfiguration());
          pc!.addTransceiver('video', direction: 'sendrecv');
          final senders = pc!.getSenders();

          pc!.onTrack.listen((evt) async {
            print('[video_echo] onTrack kind=${evt.kind} ssrc=${evt.ssrc}');
            final sender =
                senders.where((s) => s.kind == evt.kind).firstOrNull;
            if (sender == null) {
              print('[video_echo] no sender for kind=${evt.kind}');
              return;
            }
            final packetReceiver =
                await evt.receiver.replacePacketReceiver();
            final packetSender = await sender.replacePacketSender();
            var forwarded = 0;
            packetReceiver.onReceivedRtp.listen((_) {
              final packets = packetReceiver.readReceivedRtp(100);
              for (final rtp in packets) {
                if (rtp.payload.isEmpty) continue;
                packetSender.sendRtp(rtp);
                forwarded++;
                if (forwarded <= 3 || forwarded % 300 == 0) {
                  print('[video_echo] forwarded #$forwarded');
                }
              }
            });
          });

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
              .listen((s) => print('[video_echo] ICE: $s'));
          pc!.onConnectionStateChange
              .listen((s) => print('[video_echo] PC: $s'));

          await pc!.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: msg['sdp'] as String,
          ));
          final answer = await pc!.createAnswer();
          await pc!.setLocalDescription(answer);
          ws.add(jsonEncode({'type': 'answer', 'sdp': answer.sdp}));
          print('[video_echo] sent answer');

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
      print('[video_echo] WS client disconnected');
      await pc?.close();
    },
    onError: (_) async => await pc?.close(),
  );
}
