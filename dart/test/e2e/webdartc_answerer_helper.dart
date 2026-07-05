/// webdartc answerer helper process for E2E tests.
///
/// Connects to the signaling server as answerer, waits for an offer from
/// Chrome (offerer), creates an answer, and waits for a data channel
/// message exchange.
///
/// Usage:
///   dart run test/e2e/webdartc_answerer_helper.dart --port=PORT
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/webdartc.dart';

import 'e2e_settings.dart';
import 'helper_ws_client.dart';

// ── Main ──────────────────────────────────────────────────────────────────────

void main(List<String> args) async {
  int port = 8080;
  for (final arg in args) {
    if (arg.startsWith('--port=')) {
      port = int.parse(arg.substring('--port='.length));
    }
  }

  final exitCode = await _run(port);
  exit(exitCode);
}

Future<int> _run(int sigPort) async {
  final ws = await HelperWsClient.connect(sigPort);
  // Register as answerer — wait for Chrome's offer.
  ws.sendJson({'type': 'register', 'role': 'answerer'});

  final pc = PeerConnection(
    configuration: const PeerConnectionConfiguration(),
    settingEngine: e2eSettings,
  );
  pc.onIceConnectionStateChange.listen((state) {
    stderr.writeln('[answerer] ICE state: $state');
  });

  final done = Completer<int>();

  // ICE candidates → relay.
  pc.onIceCandidate.listen((evt) {
    stderr.writeln('[answerer] local ICE candidate: ${evt.candidate}');
    ws.sendJson({
      'type': 'candidate',
      'candidate': {
        'candidate': evt.candidate,
        'sdpMid': evt.sdpMid,
        'sdpMLineIndex': evt.sdpMLineIndex,
      },
    });
  });

  // Remote data channel from Chrome's offer.
  pc.onDataChannel.listen((evt) {
    final ch = evt.channel;
    stderr.writeln('[answerer] onDataChannel: label=${ch.label} id=${ch.id}');
    ch.onOpen.listen((_) {
      stdout.writeln('[answerer] DataChannel open: ${ch.label}');
      // Send a message to Chrome
      ch.send('hello from webdartc answerer');
    });
    ch.onMessage.listen((msg) {
      stdout.writeln('[answerer] received: ${msg.isBinary ? "binary" : "text"} ${msg.data.length}b');
      // Echo back
      if (msg.isBinary) {
        ch.sendBinary(msg.data);
      } else {
        ch.send(msg.text);
      }
      if (!done.isCompleted) {
        stdout.writeln('[answerer] PASS');
        done.complete(0);
      }
    });
  });

  // Process signaling messages.
  ws.messages.listen((raw) async {
    final msg = jsonDecode(raw) as Map<String, dynamic>;
    stderr.writeln('[answerer] got signal: ${msg['type']}');
    switch (msg['type'] as String?) {
      case 'offer':
        stderr.writeln('[answerer] setRemoteDescription (offer)');
        await pc.setRemoteDescription(SessionDescription(
          type: SessionDescriptionType.offer,
          sdp: msg['sdp'] as String,
        ));
        final answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        stderr.writeln('[answerer] answer SDP:\n${answer.sdp}');
        ws.sendJson({'type': 'answer', 'sdp': answer.sdp});

      case 'candidate':
        final cand = msg['candidate'];
        if (cand != null && cand is Map<String, dynamic>) {
          stderr.writeln('[answerer] addIceCandidate: ${cand['candidate']}');
          await pc.addIceCandidate(IceCandidateInit(
            candidate: cand['candidate'] as String? ?? '',
            sdpMid: cand['sdpMid'] as String? ?? '0',
            sdpMLineIndex: cand['sdpMLineIndex'] as int? ?? 0,
          ));
        }
    }
  });

  // Timeout after 30 s.
  final result = await done.future.timeout(
    const Duration(seconds: 30),
    onTimeout: () {
      stderr.writeln('[answerer] TIMEOUT');
      return 1;
    },
  );

  await pc.close();
  await ws.close();
  return result;
}
