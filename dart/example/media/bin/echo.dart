/// Dart echo peer for the media sample.
///
/// Connects to the signaling server as the offerer, declares sendrecv
/// audio+video transceivers with no local media of its own, and reflects
/// every received RTP packet back via the matching sender — the browser
/// sees its own camera echoed.
///
/// Usage:
///   dart run example/media/bin/echo.dart [--port=8080]
///
/// Open the browser at `http://127.0.0.1:<port>/?bidir=1` so it adds camera
/// tracks; without `bidir` there is nothing to echo.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/webdartc.dart';

Future<void> main(List<String> args) async {
  var port = 8080;
  for (final a in args) {
    if (a.startsWith('--port=')) port = int.parse(a.substring(7));
  }

  final ws = await WebSocket.connect('ws://127.0.0.1:$port');
  stdout.writeln('[echo] signaling connected');

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
  pc.addTransceiver('audio', direction: 'sendrecv');
  pc.addTransceiver('video', direction: 'sendrecv');
  final senders = pc.getSenders();

  pc.onTrack.listen((evt) async {
    stdout.writeln('[echo] onTrack kind=${evt.kind} ssrc=${evt.ssrc}');
    final sender = senders.where((s) => s.kind == evt.kind).firstOrNull;
    if (sender == null) {
      stdout.writeln('[echo] no sender for kind=${evt.kind}');
      return;
    }
    final packetReceiver = await evt.receiver.replacePacketReceiver();
    final packetSender = await sender.replacePacketSender();
    packetReceiver.onReceivedRtp.listen((_) {
      final packets = packetReceiver.readReceivedRtp(100);
      for (final rtp in packets) {
        if (rtp.payload.isEmpty) continue;
        packetSender.sendRtp(rtp);
      }
    });
  });

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

  pc.onIceConnectionStateChange.listen((s) => stdout.writeln('[echo] ICE: $s'));
  pc.onConnectionStateChange.listen((s) => stdout.writeln('[echo] PC: $s'));

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

  ProcessSignal.sigint.watch().listen((_) async {
    stdout.writeln('[echo] shutting down');
    await pc.close();
    await ws.close();
    exit(0);
  });
}
