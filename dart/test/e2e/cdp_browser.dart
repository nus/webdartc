/// Thin CDP (Chrome DevTools Protocol) client — launches Chrome directly
/// with --remote-debugging-port and controls it via WebSocket. No
/// chromedriver required. Shared by all E2E tests.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'chrome_for_testing.dart';

/// Controls a Chromium instance via CDP.
final class CdpBrowser {
  final Process process;
  final WebSocket _ws;
  int _nextId = 0;
  final Map<int, Completer<Map<String, dynamic>>> _pending = {};

  CdpBrowser._(this.process, this._ws) {
    _ws.listen(
      (data) {
        try {
          final msg = jsonDecode(data as String) as Map<String, dynamic>;
          final id = msg['id'] as int?;
          if (id != null && _pending.containsKey(id)) {
            _pending.remove(id)!.complete(msg);
          }
        } catch (_) {
          // Ignore CDP events and non-JSON messages.
        }
      },
      onError: (_) {},
    );
  }

  /// Launches Chrome and establishes a CDP session.
  ///
  /// [extraArgs] are appended to a minimal baseline flag set
  /// (`--headless=new`, `--no-sandbox`, loopback WebRTC). Pass whatever is
  /// needed for the specific test scenario (e.g. fake media device flags,
  /// verbose WebRTC logging).
  ///
  /// [onStderrLine], if given, receives each decoded stderr line. This is
  /// useful for surfacing Chrome-side error messages. When null, stderr is
  /// silently drained (required to prevent pipe buffer deadlock).
  static Future<CdpBrowser> create(
    ChromeForTesting cft, {
    List<String> extraArgs = const [],
    void Function(String line)? onStderrLine,
  }) async {
    final (proc, debugPort) = await cft.launchChrome(extraArgs: [
      '--headless=new',
      '--no-sandbox',
      '--allow-loopback-in-peer-connection',
      '--network-service-in-process',
      ...extraArgs,
    ]);

    proc.stdout.listen((_) {});
    if (onStderrLine != null) {
      proc.stderr
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen(onStderrLine);
    } else {
      proc.stderr.listen((_) {});
    }

    // Discover the page target WebSocket URL.
    String wsUrl;
    final client = HttpClient();
    try {
      List<dynamic> targets = [];
      for (var i = 0; i < 30; i++) {
        try {
          final req = await client
              .getUrl(Uri.parse('http://127.0.0.1:$debugPort/json/list'));
          final resp = await req.close();
          final body = await resp.transform(utf8.decoder).join();
          targets = jsonDecode(body) as List<dynamic>;
          if (targets.any((t) =>
              (t as Map<String, dynamic>)['type'] == 'page')) {
            break;
          }
        } catch (_) {
          // not ready yet
        }
        await Future<void>.delayed(const Duration(milliseconds: 200));
      }

      final page = targets.firstWhere(
        (t) => (t as Map<String, dynamic>)['type'] == 'page',
        orElse: () => throw StateError(
            'No page target found at http://127.0.0.1:$debugPort/json/list'),
      ) as Map<String, dynamic>;
      wsUrl = page['webSocketDebuggerUrl'] as String;
    } finally {
      client.close();
    }

    final ws = await WebSocket.connect(wsUrl);
    final browser = CdpBrowser._(proc, ws);
    await browser._send('Page.enable');
    return browser;
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
      throw TimeoutException('CDP command $method (id=$id) timed out');
    });
  }

  /// Navigate the page to [url] and wait briefly for it to start loading.
  Future<void> navigateTo(String url) async {
    await _send('Page.navigate', {'url': url});
    await Future<void>.delayed(const Duration(milliseconds: 500));
  }

  /// Execute a synchronous [script] and return its result.
  ///
  /// Scripts use WebDriver-style `arguments[N]` parameter access and `return`
  /// to yield a value. [args] are passed as JSON to the script.
  Future<dynamic> executeScript(String script,
      [List<dynamic> args = const []]) async {
    final argsJson = jsonEncode(args);
    final expression = '(function() { $script }).apply(null, $argsJson)';
    final result = await _send('Runtime.evaluate', {
      'expression': expression,
      'returnByValue': true,
      'awaitPromise': false,
    });
    final res = result['result'] as Map<String, dynamic>;
    if (res.containsKey('exceptionDetails')) {
      throw Exception('Script error: ${res['exceptionDetails']}');
    }
    final value = res['result'] as Map<String, dynamic>;
    return value['value'];
  }

  /// Close the browser session.
  Future<void> quit() async {
    try {
      await _send('Browser.close');
    } catch (_) {
      // Browser may already be closing.
    }
    await _ws.close();
    process.kill();
  }
}

// ── Shared polling helpers ───────────────────────────────────────────────────

/// Polls [condition] every [interval] until it returns true or [timeout]
/// elapses. Throws [TimeoutException] on timeout.
Future<void> waitFor(
  Future<bool> Function() condition, {
  Duration timeout = const Duration(seconds: 30),
  Duration interval = const Duration(milliseconds: 500),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    if (await condition()) return;
    await Future<void>.delayed(interval);
  }
  throw TimeoutException('waitFor timed out after $timeout');
}

/// Reads `window.__testState[key]` from the browser page.
Future<dynamic> browserState(CdpBrowser driver, String key) {
  return driver.executeScript(
    'var s = window.__testState || {}; return s[arguments[0]];',
    [key],
  );
}
