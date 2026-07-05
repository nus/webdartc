/// Video reflect helper using RTP Transport API (replacePacketReceiver/Sender).
///
/// Same as video_reflect_helper.dart but uses the W3C RTP Transport API path
/// that server.dart and ayame_client.dart use, to verify that code path works.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:webdartc/webdartc.dart';

import 'e2e_settings.dart';
import 'helper_ws_client.dart';

// ── VP8 keyframe detection (RFC 7741) ───────────────────────────────────────

bool _isVp8Keyframe(Uint8List payload) {
  if (payload.isEmpty) return false;
  final b0 = payload[0];
  final s = (b0 >> 4) & 1;
  final partId = b0 & 0x0F;
  if (s != 1 || partId != 0) return false;
  var off = 1;
  if ((b0 >> 7) & 1 == 1) {
    if (off >= payload.length) return false;
    final ext = payload[off++];
    if ((ext >> 7) & 1 == 1) {
      if (off >= payload.length) return false;
      off += (payload[off] & 0x80 != 0) ? 2 : 1;
    }
    if ((ext >> 6) & 1 == 1) off++;
    if ((ext >> 5) & 1 == 1) off++;
  }
  if (off >= payload.length) return false;
  return (payload[off] & 0x01) == 0;
}

// ── Main ────────────────────────────────────────────────────────────────────

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

  int reflected = 0;

  pc.onIceCandidate.listen((evt) {
    ws.sendJson({'type': 'candidate', 'candidate': {
      'candidate': evt.candidate, 'sdpMid': evt.sdpMid, 'sdpMLineIndex': evt.sdpMLineIndex,
    }});
  });

  // Use server.dart-style reflect: replacePacketReceiver + replacePacketSender
  pc.onTrack.listen((evt) async {
    stderr.writeln('[reflect] onTrack: ${evt.kind} ssrc=${evt.ssrc}');

    // Get matching sender (same pattern as server.dart)
    final senders = pc.getSenders();
    final sender = senders.where((s) => s.kind == evt.kind).firstOrNull;
    if (sender == null) {
      stderr.writeln('[reflect] WARNING: no sender for kind=${evt.kind}');
      return;
    }
    stderr.writeln('[reflect] reflecting ${evt.kind} -> sender ssrc=${sender.ssrc}');

    // W3C RTP Transport API path (same as server.dart)
    final packetReceiver = await evt.receiver.replacePacketReceiver();
    final packetSender = await sender.replacePacketSender();

    packetReceiver.onReceivedRtp.listen((_) {
      final packets = packetReceiver.readReceivedRtp(100);
      for (final rtp in packets) {
        if (rtp.payload.isEmpty) continue;
        packetSender.sendRtp(rtp);
        if (evt.kind == 'video') {
          reflected++;
          if (reflected <= 3 || reflected % 100 == 0) {
            stderr.writeln('[reflect] video #$reflected seq=${rtp.sequenceNumber}');
          }
        }
      }
    });
  });

  ws.messages.listen((raw) async {
    final msg = jsonDecode(raw) as Map<String, dynamic>;
    stderr.writeln('[reflect] signal: ${msg['type']}');
    switch (msg['type'] as String?) {
      case 'offer':
        stderr.writeln('[reflect] offer SDP:\n${msg['sdp']}');
        pc.addTransceiver('audio', direction: 'sendrecv');
        pc.addTransceiver('video', direction: 'sendrecv');

        await pc.setRemoteDescription(SessionDescription(
          type: SessionDescriptionType.offer, sdp: msg['sdp'] as String));
        final answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        // Inject short keyframe interval so Chrome sends periodic keyframes.
        // PLI via SRTCP may not reach Chrome, so we need encoder-level periodicity.
        var sdp = answer.sdp;
        sdp = sdp.replaceAllMapped(RegExp(r'(a=rtpmap:96 VP8/90000)'),
            (m) => '${m[1]}\r\na=fmtp:96 x-google-max-keyframe-interval=30');
        stderr.writeln('[reflect] answer SDP:\n$sdp');
        ws.sendJson({'type': 'answer', 'sdp': sdp});

      case 'candidate':
        final c = msg['candidate'];
        if (c != null && c is Map<String, dynamic>) {
          await pc.addIceCandidate(IceCandidateInit(
            candidate: (c['candidate'] as String?) ?? '',
            sdpMid: (c['sdpMid'] as String?) ?? '0',
            sdpMLineIndex: (c['sdpMLineIndex'] as int?) ?? 0,
          ));
        }
    }
  });

  // Keep reflecting until killed by the test runner (or 60s timeout).
  await Future<void>.delayed(const Duration(seconds: 60));
  stderr.writeln('[reflect] exiting (reflected=$reflected video packets)');
  await pc.close();
  await ws.close();
  return 0;
}
