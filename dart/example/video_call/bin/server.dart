/// HTTP + WebSocket signaling server for the video_call sample.
///
/// Serves the browser client HTML on `/` and relays signaling JSON messages
/// between two WebSocket clients.
///
/// Usage:
///   dart run example/video_call/bin/server.dart [--port=8080]
library;

import 'dart:async';
import 'dart:io';

Future<void> main(List<String> args) async {
  var port = 8080;
  for (final a in args) {
    if (a.startsWith('--port=')) port = int.parse(a.substring(7));
  }

  final webRoot = _resolveWebRoot();

  final server = await HttpServer.bind(InternetAddress.anyIPv4, port);
  stdout.writeln('video_call server listening on http://127.0.0.1:$port');
  stdout.writeln('web root: $webRoot');

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
      await _serveStatic(req, webRoot);
    }
  }
}

String _resolveWebRoot() {
  final script = Platform.script.toFilePath();
  final dir = Directory(script).parent.parent;
  return '${dir.path}/web';
}

Future<void> _serveStatic(HttpRequest req, String root) async {
  var path = req.uri.path;
  if (path == '/' || path.isEmpty) path = '/index.html';
  final file = File('$root$path');
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
