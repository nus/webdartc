/// HTTP + WebSocket signaling relay.
///
/// Serves the browser client HTML on `/` and blindly forwards every JSON
/// message between any two connected WebSocket clients. Used to pair two
/// peers that both implement the WebRTC offer/answer/candidate dance
/// themselves — e.g. the `flutter/example/` app talking to a browser.
///
/// For pure browser ↔ Dart demos, prefer the self-contained
/// `example/video_sender/` or `example/video_receiver/` instead.
///
/// Usage:
///   dart run example/signaling/server.dart [--port=8080]
library;

import 'dart:async';
import 'dart:io';

Future<void> main(List<String> args) async {
  var port = 8080;
  for (final a in args) {
    if (a.startsWith('--port=')) port = int.parse(a.substring(7));
  }

  final server = await HttpServer.bind(InternetAddress.anyIPv4, port);
  stdout.writeln('signaling relay listening on http://127.0.0.1:$port');

  final clients = <WebSocket>[];

  await for (final req in server) {
    if (WebSocketTransformer.isUpgradeRequest(req)) {
      final ws = await WebSocketTransformer.upgrade(req);
      clients.add(ws);
      ws.listen(
        (data) {
          if (data is String) {
            for (final c in clients) {
              if (!identical(c, ws)) c.add(data);
            }
          }
        },
        onDone: () => clients.remove(ws),
        onError: (_) => clients.remove(ws),
      );
    } else {
      await _serveStatic(req);
    }
  }
}

String _scriptDir() {
  final script = Platform.script.toFilePath();
  return script.substring(0, script.lastIndexOf('/'));
}

Future<void> _serveStatic(HttpRequest req) async {
  var path = req.uri.path;
  if (path == '/' || path.isEmpty) path = '/index.html';
  final file = File('${_scriptDir()}$path');
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
