/// Browser mic → Dart speaker over WebRTC.
///
/// The browser captures audio via `getUserMedia({audio:true})` and sends
/// it (Opus / SRTP) to the Dart server. The W3C receive path
/// (`onTrack` → `track.onAudioData`) jitter-buffers, depacketises and
/// decodes inside the track; this example just plays the decoded PCM
/// through macOS AudioQueue via [AudioRenderer].
///
/// Usage:
///   dart run example/audio_receive/server.dart [--port=8080]
///
/// Then open `http://127.0.0.1:<port>` in Chrome and click Start.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/src/media/macos/avf_audio_renderer.dart';
import 'package:webdartc/webdartc.dart';

int _port = 8080;

Future<void> main(List<String> args) async {
  for (final a in args) {
    if (a.startsWith('--port=')) _port = int.parse(a.substring(7));
  }
  if (!Platform.isMacOS) {
    stderr.writeln('This example only runs on macOS (uses AudioQueue).');
    exit(64);
  }

  // The Opus backend is auto-registered by PeerConnection, so the W3C receive
  // path decodes out of the box — no explicit registerOpusCodec().

  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  stdout.writeln('audio_receive server listening on http://127.0.0.1:$_port');
  stdout.writeln('Open the URL in Chrome and click Start.');

  await for (final req in server) {
    if (WebSocketTransformer.isUpgradeRequest(req)) {
      final ws = await WebSocketTransformer.upgrade(req);
      _handleWs(ws);
    } else {
      _serveHtml(req);
    }
  }
}

String _scriptDir() {
  final script = Platform.script.toFilePath();
  return script.substring(0, script.lastIndexOf('/'));
}

void _serveHtml(HttpRequest req) {
  final path = '${_scriptDir()}/index.html';
  String html;
  try {
    html = File(path).readAsStringSync();
  } on FileSystemException {
    req.response
      ..statusCode = 404
      ..write('index.html not found at $path')
      ..close();
    return;
  }
  req.response
    ..headers.contentType = ContentType.html
    ..write(html.replaceAll("params.get('port') || '8080'", "'$_port'"))
    ..close();
}

// Browser Chrome's default offer is opus/48000/2 — match it so the
// decoder doesn't need to up/down-mix.
const _sampleRate = 48000;
const _channels = 2;

void _handleWs(WebSocket ws) {
  stdout.writeln('[ws] client connected');

  PeerConnection? pc;
  AudioRenderer? renderer;
  StreamSubscription<AudioData>? audioSub;

  Future<void> teardown() async {
    await audioSub?.cancel();
    audioSub = null;
    renderer?.close();
    renderer = null;
    await pc?.close();
    pc = null;
  }

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type']) {
        case 'offer':
          stdout.writeln('[sig] offer received');
          pc = PeerConnection(
              configuration: const PeerConnectionConfiguration());

          pc!.addTransceiver('audio',
              direction: 'recvonly', preferredCodecs: ['opus']);

          pc!.onTrack.listen((evt) {
            if (evt.kind != 'audio') return;
            stdout.writeln('[track] ssrc=${evt.ssrc} — wiring playback');
            final track = evt.track;
            if (track == null) {
              stderr.writeln('[track] no Opus decoder available');
              return;
            }
            renderer ??=
                AudioRenderer(sampleRate: _sampleRate, channels: _channels);
            // Subscribing starts the jitter→depacketize→decode pipeline; the
            // track emits decoded PCM as [AudioData].
            var frames = 0;
            audioSub = track.onAudioData.listen((audio) {
              renderer!.push(audio);
              frames++;
              if (frames % 100 == 0) {
                stdout.writeln('[audio] played $frames decoded frames');
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
              },
            }));
          });
          pc!.onIceConnectionStateChange
              .listen((s) => stdout.writeln('[ice] $s'));
          pc!.onConnectionStateChange
              .listen((s) => stdout.writeln('[conn] $s'));

          await pc!.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: msg['sdp'] as String,
          ));
          final answer = await pc!.createAnswer();
          await pc!.setLocalDescription(answer);
          ws.add(jsonEncode({'type': 'answer', 'sdp': answer.sdp}));
          stdout.writeln('[sig] answer sent');

        case 'candidate':
          final cand = msg['candidate'];
          if (cand is Map<String, dynamic> && pc != null) {
            await pc!.addIceCandidate(IceCandidateInit(
              candidate: (cand['candidate'] as String?) ?? '',
              sdpMid: (cand['sdpMid'] as String?) ?? '0',
              sdpMLineIndex: (cand['sdpMLineIndex'] as int?) ?? 0,
            ));
          }
      }
    },
    onDone: () async {
      stdout.writeln('[ws] client disconnected');
      await teardown();
    },
    onError: (_) async => teardown(),
  );
}
