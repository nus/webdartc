/// webdartc video reflect helper for E2E tests.
///
/// Connects as answerer, receives Chrome's video, reflects RTP back.
///
/// Usage:
///   dart run test/e2e/video_reflect_helper.dart --port=PORT
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
    if (arg.startsWith('--port=')) port = int.parse(arg.substring(7));
  }
  exit(await _run(port));
}

Future<int> _run(int sigPort) async {
  final ws = await HelperWsClient.connect(sigPort);
  ws.sendJson({'type': 'register', 'role': 'answerer'});

  final pc = PeerConnection(
    configuration: const PeerConnectionConfiguration(),
    settingEngine: e2eSettings,
  );
  pc.onIceConnectionStateChange.listen((s) => stderr.writeln('[reflect] ICE: $s'));

  RtpSender? videoSender;
  int reflected = 0;
  bool passed = false;
  final done = Completer<int>();

  pc.onIceCandidate.listen((evt) {
    ws.sendJson({'type': 'candidate', 'candidate': {
      'candidate': evt.candidate, 'sdpMid': evt.sdpMid, 'sdpMLineIndex': evt.sdpMLineIndex,
    }});
  });

  // Reflect received video RTP back, keep running for BWE measurement.
  pc.onTrack.listen((evt) {
    stderr.writeln('[reflect] onTrack: ${evt.kind} ssrc=${evt.ssrc}');
    if (evt.kind == 'video' && videoSender != null) {
      evt.receiver.onRtp.listen((rtp) {
        videoSender!.sendRtp(rtp.payload, marker: rtp.marker, timestamp: rtp.timestamp);
        reflected++;
        if (reflected == 50 && !passed) {
          passed = true;
          stdout.writeln('[reflect] PASS (reflected $reflected video packets)');
          // Keep running — don't complete yet so Chrome can measure BWE.
        }
      });
    }
  });

  ws.messages.listen((raw) async {
    final msg = jsonDecode(raw) as Map<String, dynamic>;
    stderr.writeln('[reflect] signal: ${msg['type']}');
    switch (msg['type'] as String?) {
      case 'offer':
        // Add audio (recvonly) + video (sendrecv) transceivers
        pc.addTransceiver('audio', direction: 'recvonly');
        pc.addTransceiver('video', direction: 'sendrecv');
        videoSender = pc.getSenders().where((s) => s.kind == 'video').firstOrNull;

        await pc.setRemoteDescription(SessionDescription(
          type: SessionDescriptionType.offer, sdp: msg['sdp'] as String));
        final answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        stderr.writeln('[reflect] answer SDP:\n${answer.sdp}');
        ws.sendJson({'type': 'answer', 'sdp': answer.sdp});

      case 'candidate':
        final c = msg['candidate'];
        if (c != null && c is Map<String, dynamic>) {
          await pc.addIceCandidate(IceCandidateInit(
            candidate: (c['candidate'] as String?) ?? '',
            sdpMid: (c['sdpMid'] as String?) ?? '0',
            sdpMLineIndex: (c['sdpMLineIndex'] as int?) ?? 0,
          ));
        }

      case 'close':
        if (!done.isCompleted) done.complete(passed ? 0 : 1);
    }
  });

  // Keep connection alive for up to 60s for BWE measurement.
  // Test side will close via signaling 'close' message or timeout.
  final result = await done.future.timeout(
    const Duration(seconds: 60),
    onTimeout: () {
      stderr.writeln('[reflect] timeout (reflected=$reflected passed=$passed)');
      return passed ? 0 : 1;
    },
  );
  await pc.close();
  await ws.close();
  return result;
}
