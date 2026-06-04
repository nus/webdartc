/// Shared static-file serving for the standalone webdartc examples.
///
/// Each example under `example/` is a self-contained `dart run` entrypoint
/// that serves its own `index.html` (sitting next to the `server.dart`)
/// alongside relaying WebSocket signaling. This factors out the HTTP
/// file-serving half they all share so the example files stay focused on
/// the WebRTC peer logic.
library;

import 'dart:io';

/// Directory holding the running example's `server.dart` (and its
/// `index.html`). Resolved from `Platform.script`, which points at the
/// entrypoint being run — not this helper file. Uses the URI's parent so
/// it is separator-correct on Windows (`toFilePath()` there yields
/// backslashes, which a `lastIndexOf('/')` split would miss).
String exampleScriptDir() => File.fromUri(Platform.script).parent.path;

/// Serves a static file from the example's script directory. Maps `/` to
/// `/index.html` and 404s anything missing. Content types cover the
/// html/js/css the example pages use.
Future<void> serveExampleStatic(HttpRequest req) async {
  var path = req.uri.path;
  if (path == '/' || path.isEmpty) path = '/index.html';
  final file = File('${exampleScriptDir()}$path');
  if (!await file.exists()) {
    req.response.statusCode = HttpStatus.notFound;
    await req.response.close();
    return;
  }
  final ext = path.split('.').last;
  req.response.headers.contentType = ContentType.parse(switch (ext) {
    'html' => 'text/html; charset=utf-8',
    'js' => 'application/javascript; charset=utf-8',
    'css' => 'text/css; charset=utf-8',
    _ => 'application/octet-stream',
  });
  await req.response.addStream(file.openRead());
  await req.response.close();
}
