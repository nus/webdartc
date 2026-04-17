/// E2E test for the video_call sample.
///
/// Runs the sample end-to-end:
///   1. spawns example/video_call/bin/server.dart (HTTP + signaling WS)
///   2. launches Chrome, points it at the server's root
///   3. spawns example/video_call/bin/sender.dart
///   4. polls the browser's inbound-rtp stats until frames decode
@Tags(['e2e'])
@Timeout(Duration(seconds: 120))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'chrome_for_testing.dart';

// ── Minimal CDP client (duplicated intentionally from e2e_test.dart to keep
//    this file self-contained) ────────────────────────────────────────────────

final class _Cdp {
  final Process _process;
  final WebSocket _ws;
  int _nextId = 0;
  final Map<int, Completer<Map<String, dynamic>>> _pending = {};

  _Cdp._(this._process, this._ws) {
    _ws.listen(
      (data) {
        try {
          final msg = jsonDecode(data as String) as Map<String, dynamic>;
          final id = msg['id'] as int?;
          if (id != null && _pending.containsKey(id)) {
            _pending.remove(id)!.complete(msg);
          }
        } catch (_) {}
      },
      onError: (_) {},
    );
  }

  static Future<_Cdp> create(ChromeForTesting cft) async {
    final (proc, debugPort) = await cft.launchChrome(extraArgs: const [
      '--headless=new',
      '--no-sandbox',
      '--allow-loopback-in-peer-connection',
      '--network-service-in-process',
    ]);
    proc.stdout.listen((_) {});
    proc.stderr.listen((_) {});

    String wsUrl;
    final client = HttpClient();
    try {
      Map<String, dynamic>? page;
      for (var i = 0; i < 30; i++) {
        try {
          final req = await client
              .getUrl(Uri.parse('http://127.0.0.1:$debugPort/json/list'));
          final resp = await req.close();
          final body = await resp.transform(utf8.decoder).join();
          final targets = jsonDecode(body) as List<dynamic>;
          page = targets
              .cast<Map<String, dynamic>>()
              .where((t) => t['type'] == 'page')
              .cast<Map<String, dynamic>?>()
              .firstWhere((_) => true, orElse: () => null);
          if (page != null) break;
        } catch (_) {}
        await Future<void>.delayed(const Duration(milliseconds: 200));
      }
      if (page == null) throw StateError('No CDP page target found');
      wsUrl = page['webSocketDebuggerUrl'] as String;
    } finally {
      client.close();
    }

    final ws = await WebSocket.connect(wsUrl);
    final cdp = _Cdp._(proc, ws);
    await cdp._send('Page.enable');
    return cdp;
  }

  Future<Map<String, dynamic>> _send(String method,
      [Map<String, dynamic>? params]) {
    final id = ++_nextId;
    final completer = Completer<Map<String, dynamic>>();
    _pending[id] = completer;
    _ws.add(jsonEncode({
      'id': id,
      'method': method,
      if (params != null) 'params': params,
    }));
    return completer.future
        .timeout(const Duration(seconds: 10), onTimeout: () {
      _pending.remove(id);
      throw TimeoutException('CDP $method timed out');
    });
  }

  Future<void> navigateTo(String url) async {
    await _send('Page.navigate', {'url': url});
    await Future<void>.delayed(const Duration(milliseconds: 500));
  }

  Future<dynamic> eval(String expression) async {
    final r = await _send('Runtime.evaluate', {
      'expression': expression,
      'returnByValue': true,
      'awaitPromise': false,
    });
    final res = r['result'] as Map<String, dynamic>;
    if (res.containsKey('exceptionDetails')) {
      throw Exception('eval error: ${res['exceptionDetails']}');
    }
    final value = res['result'] as Map<String, dynamic>;
    return value['value'];
  }

  Future<void> quit() async {
    try {
      await _send('Browser.close');
    } catch (_) {}
    await _ws.close();
    _process.kill();
  }
}

Future<void> _waitUntil(Future<bool> Function() cond,
    {Duration timeout = const Duration(seconds: 30),
    Duration interval = const Duration(milliseconds: 500)}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    if (await cond()) return;
    await Future<void>.delayed(interval);
  }
  throw TimeoutException('waitUntil timed out after $timeout');
}

// ── Subprocess launcher ──────────────────────────────────────────────────────

Future<Process> _spawnDart(String script, List<String> args) async {
  return Process.start(
    Platform.resolvedExecutable,
    ['run', script, ...args],
    workingDirectory: Directory.current.path,
  );
}

Future<int> _findFreePort() async {
  final s = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = s.port;
  await s.close();
  return port;
}

// ── Test ─────────────────────────────────────────────────────────────────────

void main() {
  late ChromeForTesting cft;

  setUpAll(() async {
    cft = await ChromeForTesting.ensureAvailable();
  });

  for (final codec in ['vp8', 'h264']) {
    test('browser decodes $codec video frames from Dart sender', () async {
    final port = await _findFreePort();

    // 1. Start the sample server.
    final server = await _spawnDart(
      'example/video_call/bin/server.dart',
      ['--port=$port'],
    );
    final serverOut = <String>[];
    server.stdout.transform(utf8.decoder).listen((line) {
      serverOut.add(line);
      // ignore: avoid_print
      print('[server] $line');
    });
    server.stderr.transform(utf8.decoder).listen((line) {
      // ignore: avoid_print
      print('[server-err] $line');
    });

    // Wait for server to be ready by probing the port.
    await _waitUntil(
      () async {
        try {
          final sock = await Socket.connect('127.0.0.1', port,
              timeout: const Duration(milliseconds: 500));
          sock.destroy();
          return true;
        } catch (_) {
          return false;
        }
      },
      timeout: const Duration(seconds: 10),
    );

    // 2. Launch Chrome and navigate to the server root.
    final cdp = await _Cdp.create(cft);
    await cdp.navigateTo('http://127.0.0.1:$port/');

    // Skip if the browser build lacks a decoder for the requested codec
    // (e.g. Playwright's Chromium build has no H.264 decoder).
    final codecsRaw = await cdp.eval(
      '(() => { const c = RTCRtpReceiver.getCapabilities("video").codecs; '
      'return c.map(x => x.mimeType).join(","); })()',
    );
    final codecList = (codecsRaw as String? ?? '').toLowerCase();
    final wanted = codec == 'h264' ? 'video/h264' : 'video/vp8';
    if (!codecList.contains(wanted)) {
      markTestSkipped('browser lacks $wanted decoder (codecs=$codecList)');
      await cdp.quit();
      server.kill();
      await server.exitCode
          .timeout(const Duration(seconds: 3), onTimeout: () => -1);
      return;
    }

    // 3. Start the sender.
    final sender = await _spawnDart(
      'example/video_call/bin/sender.dart',
      ['--port=$port', '--codec=$codec'],
    );
    sender.stdout.transform(utf8.decoder).listen((line) {
      // ignore: avoid_print
      print('[sender] $line');
    });
    sender.stderr.transform(utf8.decoder).listen((line) {
      // ignore: avoid_print
      print('[sender-err] $line');
    });

    try {
      // 4. Poll browser until it reports decoded video frames.
      await _waitUntil(
        () async {
          final decoded = await cdp.eval(
              '(window.__testState || {}).videoFramesDecoded || 0');
          final ice = await cdp.eval(
              '(window.__testState || {}).iceState || ""');
          // ignore: avoid_print
          print('[test] ice=$ice framesDecoded=$decoded');
          final n = decoded is num ? decoded.toInt() : 0;
          return n > 0;
        },
        timeout: const Duration(seconds: 60),
        interval: const Duration(seconds: 2),
      );

      final finalDecoded = await cdp.eval(
          '(window.__testState || {}).videoFramesDecoded || 0');
      expect((finalDecoded as num).toInt(), greaterThan(0));
    } finally {
      sender.kill();
      await cdp.quit();
      server.kill();
      await sender.exitCode
          .timeout(const Duration(seconds: 3), onTimeout: () => -1);
      await server.exitCode
          .timeout(const Duration(seconds: 3), onTimeout: () => -1);
    }
    });
  }
}
