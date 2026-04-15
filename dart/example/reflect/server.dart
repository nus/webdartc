/// webdartc reflect server — receives audio+video from a browser and sends them back.
///
/// Usage:
///   dart run example/reflect/server.dart [--port=8080]
///
/// Then open http://localhost:<port> in Chrome.
library;

import 'dart:convert';
import 'dart:io';
import 'package:webdartc/webdartc.dart';

// ── Configuration ────────────────────────────────────────────────────────────

int _port = 8080;

// ── Main ──────────────────────────────────────────────────────────────────────

void main(List<String> args) async {
  for (final arg in args) {
    if (arg.startsWith('--port=')) _port = int.parse(arg.substring(7));
  }

  // Start combined HTTP + WebSocket server.
  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  print('Reflect server listening on http://127.0.0.1:$_port');
  print('Open the URL above in Chrome to start.');

  await for (final req in server) {
    if (WebSocketTransformer.isUpgradeRequest(req)) {
      final ws = await WebSocketTransformer.upgrade(req);
      _handleWs(ws);
    } else {
      _serveHtml(req);
    }
  }
}

// ── HTTP: serve index.html ───────────────────────────────────────────────────

void _serveHtml(HttpRequest req) {
  final htmlPath = '${_scriptDir()}/index.html';
  final file = File(htmlPath);
  if (!file.existsSync()) {
    req.response
      ..statusCode = 404
      ..write('index.html not found at $htmlPath')
      ..close();
    return;
  }
  final html = file.readAsStringSync().replaceAll(
    "params.get('port') || '8080'",
    "'$_port'",
  );
  req.response
    ..headers.contentType = ContentType.html
    ..write(html)
    ..close();
}

String _scriptDir() {
  // Resolve relative to this script's location.
  final script = Platform.script.toFilePath();
  return script.substring(0, script.lastIndexOf('/'));
}

// ── WebSocket signaling + webdartc peer ──────────────────────────────────────

void _handleWs(WebSocket ws) {
  print('[ws] Client connected');

  PeerConnection? pc;

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;

      switch (msg['type']) {
        case 'register':
          print('[ws] Registered: ${msg['role']}');

        case 'offer':
          print('[sig] Received offer');

          // Create PeerConnection
          pc = PeerConnection(
            configuration: const PeerConnectionConfiguration(),
          );

          // Add sendrecv transceivers for audio and video.
          pc!.addTransceiver('audio', direction: 'sendrecv');
          pc!.addTransceiver('video', direction: 'sendrecv');

          // ICE candidates → browser
          pc!.onIceCandidate.listen((evt) {
            ws.add(
              jsonEncode({
                'type': 'candidate',
                'candidate': {
                  'candidate': evt.candidate,
                  'sdpMid': evt.sdpMid,
                  'sdpMLineIndex': evt.sdpMLineIndex,
                },
              }),
            );
          });

          // Log state changes
          pc!.onIceConnectionStateChange.listen((s) => print('[ice] $s'));
          pc!.onConnectionStateChange.listen((s) => print('[conn] $s'));

          // Reflect: when a track arrives, use RTP Transport API to receive
          // packets and reflect them back via the matching sender.
          final senders = pc!.getSenders();
          for (final s in senders) {
            print('[setup] sender: kind=${s.kind} ssrc=${s.ssrc} pt=${s.payloadType}');
          }

          pc!.onTrack.listen((evt) async {
            print('[track] kind=${evt.kind} ssrc=${evt.ssrc}');
            final sender = senders.where((s) => s.kind == evt.kind).firstOrNull;
            if (sender == null) {
              print('[track] WARNING: no sender found for kind=${evt.kind}');
              return;
            }
            print('[track] reflecting ${evt.kind} → sender ssrc=${sender.ssrc}');

            // W3C RTP Transport API: packet-level receive and send.
            final packetReceiver = await evt.receiver.replacePacketReceiver();
            final packetSender = await sender.replacePacketSender();

            // Reflect all non-empty packets. PLI (sent on track creation)
            // triggers a keyframe from Chrome; until then, delta frames flow
            // through and the decoder recovers once the keyframe arrives.
            packetReceiver.onReceivedRtp.listen((_) {
              final packets = packetReceiver.readReceivedRtp(100);
              for (final rtp in packets) {
                if (rtp.payload.isEmpty) continue;
                packetSender.sendRtp(rtp);
              }
            });
          });

          // Process offer → create answer
          await pc!.setRemoteDescription(
            SessionDescription(
              type: SessionDescriptionType.offer,
              sdp: msg['sdp'] as String,
            ),
          );
          final answer = await pc!.createAnswer();
          await pc!.setLocalDescription(answer);

          ws.add(jsonEncode({'type': 'answer', 'sdp': answer.sdp}));
          print('[sig] Sent answer');

        case 'candidate':
          final cand = msg['candidate'];
          if (cand != null && cand is Map<String, dynamic> && pc != null) {
            await pc!.addIceCandidate(
              IceCandidateInit(
                candidate: (cand['candidate'] as String?) ?? '',
                sdpMid: (cand['sdpMid'] as String?) ?? '0',
                sdpMLineIndex: (cand['sdpMLineIndex'] as int?) ?? 0,
              ),
            );
          }
      }
    },
    onDone: () async {
      print('[ws] Client disconnected');
      await pc?.close();
    },
    onError: (_) async {
      await pc?.close();
    },
  );
}

