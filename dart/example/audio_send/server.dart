/// webdartc audio-send example — streams a 440 Hz sine tone to a browser
/// over Opus / SRTP / DTLS / ICE.
///
/// Usage:
///   dart run example/audio_send/server.dart [--port=8080]
///
/// Then open http://localhost:<port> in Chrome and click "Start" to hear
/// the tone.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/webdartc.dart';

int _port = 8080;

void main(List<String> args) async {
  for (final arg in args) {
    if (arg.startsWith('--port=')) _port = int.parse(arg.substring(7));
  }

  registerOpusCodec();

  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  print('Audio-send server listening on http://127.0.0.1:$_port');
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

void _serveHtml(HttpRequest req) {
  final htmlPath = '${_scriptDir()}/index.html';
  String html;
  try {
    html = File(htmlPath).readAsStringSync();
  } on FileSystemException {
    req.response
      ..statusCode = 404
      ..write('index.html not found at $htmlPath')
      ..close();
    return;
  }
  req.response
    ..headers.contentType = ContentType.html
    ..write(html.replaceAll(
      "params.get('port') || '8080'",
      "'$_port'",
    ))
    ..close();
}

String _scriptDir() {
  final script = Platform.script.toFilePath();
  return script.substring(0, script.lastIndexOf('/'));
}

void _handleWs(WebSocket ws) {
  print('[ws] Client connected');

  PeerConnection? pc;
  StreamSubscription<AudioData>? audioSub;
  AudioEncoder? encoder;

  Future<void> teardown() async {
    await audioSub?.cancel();
    audioSub = null;
    encoder?.close();
    encoder = null;
    await pc?.close();
    pc = null;
  }

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;

      switch (msg['type']) {
        case 'register':
          print('[ws] Registered: ${msg['role']}');

        case 'offer':
          print('[sig] Received offer');
          pc = PeerConnection(configuration: const PeerConnectionConfiguration());

          pc!.addTransceiver('audio', direction: 'sendonly');
          final sender = pc!.getSenders().firstWhere((s) => s.kind == 'audio');
          print('[setup] sender: ssrc=${sender.ssrc} pt=${sender.payloadType}');

          pc!.onIceCandidate.listen((evt) {
            ws.add(jsonEncode({
              'type': 'candidate',
              'candidate': {
                'candidate': evt.candidate,
                'sdpMid': evt.sdpMid,
                'sdpMLineIndex': evt.sdpMLineIndex,
              },
            }));
          });

          pc!.onIceConnectionStateChange.listen((s) => print('[ice] $s'));
          pc!.onConnectionStateChange.listen((s) {
            print('[conn] $s');
            if (s == PeerConnectionState.connected) {
              final stream = _startAudioStream(sender);
              encoder = stream.encoder;
              audioSub = stream.sub;
            }
          });

          await pc!.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: msg['sdp'] as String,
          ));
          final answer = await pc!.createAnswer();
          await pc!.setLocalDescription(answer);

          ws.add(jsonEncode({'type': 'answer', 'sdp': answer.sdp}));
          print('[sig] Sent answer');

        case 'candidate':
          final cand = msg['candidate'];
          if (cand != null && cand is Map<String, dynamic> && pc != null) {
            await pc!.addIceCandidate(IceCandidateInit(
              candidate: (cand['candidate'] as String?) ?? '',
              sdpMid: (cand['sdpMid'] as String?) ?? '0',
              sdpMLineIndex: (cand['sdpMLineIndex'] as int?) ?? 0,
            ));
          }
      }
    },
    onDone: () async {
      print('[ws] Client disconnected');
      await teardown();
    },
    onError: (_) async => teardown(),
  );
}

/// 50 frames × 20 ms = 1 second; matches the encoder's frame rate so the log
/// fires once per wall-clock second.
const int _logEveryNFrames = 50;

({AudioEncoder encoder, StreamSubscription<AudioData> sub}) _startAudioStream(
    RtpSender sender) {
  print('[audio] Starting 440 Hz tone');
  var sent = 0;
  final encoder = AudioEncoder(
    output: (chunk, _) {
      sender.sendRtp(chunk.data);
      sent++;
      if (sent % _logEveryNFrames == 0) print('[audio] sent $sent Opus frames');
    },
    error: (e) => print('[audio] encoder error: $e'),
  );
  encoder.configure(const AudioEncoderConfig(
    codec: 'opus',
    sampleRate: 48000,
    numberOfChannels: 2,
  ));

  final sub = FakeAudioSource().start().listen(encoder.encode);
  return (encoder: encoder, sub: sub);
}
