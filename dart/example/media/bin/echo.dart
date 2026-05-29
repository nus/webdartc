/// Self-contained Dart echo peer for the media sample.
///
/// HTTP + WS + Dart peer in one binary. Serves `web/index.html` on `/`,
/// accepts a WebSocket upgrade, waits for the browser's `{type:'ready'}`,
/// then offers `sendrecv` video with no local source and forwards every
/// received RTP packet back via the matching sender — the browser sees
/// its own camera echoed.
///
/// Usage:
///   dart run example/media/bin/echo.dart [--port=8080]
///
/// Open `http://127.0.0.1:<port>/?bidir=1` in Chrome so it adds camera
/// tracks; without `bidir` there is nothing to echo.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/webdartc.dart';

int _port = 8080;

Future<void> main(List<String> args) async {
  for (final a in args) {
    if (a.startsWith('--port=')) _port = int.parse(a.substring(7));
  }

  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  stdout.writeln('[echo] listening on http://127.0.0.1:$_port');
  stdout.writeln('[echo] open http://127.0.0.1:$_port/?bidir=1 in Chrome '
      '(echo needs a browser-sourced track to reflect)');

  await for (final req in server) {
    if (WebSocketTransformer.isUpgradeRequest(req)) {
      final ws = await WebSocketTransformer.upgrade(req);
      unawaited(_handleWs(ws));
    } else {
      await _serveStatic(req);
    }
  }
}

Future<void> _serveStatic(HttpRequest req) async {
  final path = req.uri.path == '/' ? '/index.html' : req.uri.path;
  final file = File('${_webRoot()}$path');
  if (!await file.exists()) {
    req.response.statusCode = HttpStatus.notFound;
    await req.response.close();
    return;
  }
  final ext = path.split('.').last;
  final contentType = switch (ext) {
    'html' => 'text/html; charset=utf-8',
    'js' => 'application/javascript; charset=utf-8',
    'css' => 'text/css; charset=utf-8',
    _ => 'application/octet-stream',
  };
  req.response.headers.contentType = ContentType.parse(contentType);
  await req.response.addStream(file.openRead());
  await req.response.close();
}

String _webRoot() {
  final script = Platform.script.toFilePath();
  final dir = Directory(script).parent.parent;
  return '${dir.path}/web';
}

Future<void> _handleWs(WebSocket ws) async {
  stdout.writeln('[echo] WS client connected');

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
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

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type'] as String?) {
        // Browser sends `ready` after attaching its onmessage handler and
        // (in `?bidir=1`) finishing getUserMedia. Only then is it safe to
        // push the offer.
        case 'ready':
          stdout.writeln('[echo] browser ready — sending offer');
          final offer = await pc.createOffer();
          await pc.setLocalDescription(offer);
          ws.add(jsonEncode({'type': 'offer', 'sdp': offer.sdp}));
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
    },
    onDone: () async {
      stdout.writeln('[echo] WS client disconnected');
      await pc.close();
    },
    onError: (_) async => await pc.close(),
  );
}
