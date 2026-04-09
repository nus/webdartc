/// E2E tests for webdartc with Firefox.
///
/// Mirrors the Chrome E2E test scenarios using Firefox via GeckoDriver
/// (W3C WebDriver protocol) instead of CDP.
///
/// Scenarios:
///   1.  Data channel: webdartc (offerer) ↔ Firefox (answerer)
///   3.  Trickle ICE: validate addIceCandidate() incremental flow
///
/// Skipped scenarios (known limitations):
///   1b. Firefox offerer — ICE controlled agent race (non-candidate STUN port)
///   2.  Media — Firefox negotiates SRTP GCM (not yet supported)
///   4.  Media echo — same as 1b (Firefox offerer)
///   Packet loss — UDP proxy interop with Firefox STUN port behavior
///
/// Requires Firefox and GeckoDriver on PATH.
/// Run with:
///   dart test test/e2e/e2e_firefox_test.dart --timeout=120s
@Tags(['e2e'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'firefox_for_testing.dart';
import 'signaling_server/signaling_server.dart';
import 'webdriver_session.dart';

// ── Poll helper ───────────────────────────────────────────────────────────────

/// Polls [condition] every [interval] until it returns true or [timeout] elapses.
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

/// Reads window.__testState[key] from the browser page.
Future<dynamic> browserState(WebDriverSession driver, String key) {
  return driver.executeScript(
    'var s = window.__testState || {}; return s[arguments[0]];',
    [key],
  );
}

// ── File server for browser_client/index.html ─────────────────────────────────

/// Starts a minimal HTTP server serving the given HTML file at every path.
Future<(HttpServer, int)> serveHtml(String htmlFilePath) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final htmlContent = await File(htmlFilePath).readAsString();
  server.listen((HttpRequest req) async {
    req.response
      ..statusCode = HttpStatus.ok
      ..headers.contentType = ContentType.html
      ..write(htmlContent);
    await req.response.close();
  });
  return (server, server.port);
}

// ── Test main ────────────────────────────────────────────────────────────────

void main() {
  late FirefoxForTesting ff;

  setUpAll(() async {
    ff = await FirefoxForTesting.ensureAvailable();
  });

  tearDownAll(() {
    ff.dispose();
  });

  Future<WebDriverSession> createFirefoxSession() {
    return WebDriverSession.create(
      geckodriverPort: ff.geckodriverPort,
      firefoxBinaryPath: ff.firefoxBinaryPath,
    );
  }

  // ── Scenario 1: Data channel webdartc ↔ Firefox ───────────────────────────

  group('Scenario 1 — data channel (webdartc offerer ↔ Firefox answerer)', () {
    SignalingServer? sigServer;
    HttpServer? htmlServer;
    int htmlPort = 0;
    WebDriverSession? driver;

    setUp(() async {
      sigServer = await SignalingServer.start();
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await createFirefoxSession();
    });

    tearDown(() async {
      await driver?.quit();
      await htmlServer?.close(force: true);
      await sigServer?.close();
    });

    test('open, send text 1KB, send binary 64KB, receive echoes', () async {
      final d = driver!;
      final sig = sigServer!;

      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=answerer&scenario=data';
      await d.navigateTo(url);

      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      final offererFuture = _runWebdartcOfferer(sig.port);

      try {
        await waitFor(
          () async {
            final v = await browserState(d, 'iceState');
            return v == 'connected' || v == 'completed';
          },
          timeout: const Duration(seconds: 30),
          interval: const Duration(seconds: 3),
        );
      } catch (e) {
        await _printBrowserLog(d);
        rethrow;
      }

      await waitFor(
        () async => await browserState(d, 'dcOpen') == true,
        timeout: const Duration(seconds: 30),
      );

      await offererFuture.timeout(const Duration(seconds: 30));

      final received = await browserState(d, 'receivedCount');
      expect(received, greaterThanOrEqualTo(2));
    });
  });

  // Scenario 1b (Firefox offerer ↔ webdartc answerer) is skipped.
  // Firefox sends ICE binding requests from a different port than its
  // candidates, causing USE-CANDIDATE nomination to be lost when the
  // webdartc controlled agent creates peer-reflexive candidates. This is
  // an ICE state machine limitation with early STUN from non-candidate ports.

  // Scenario 2 (media) is skipped: Firefox negotiates SRTP_AEAD_AES_128_GCM
  // which webdartc does not yet support. Data channel tests (ICE+DTLS+SCTP)
  // are the primary Firefox interop validation.

  // ── Scenario 3: Trickle ICE ───────────────────────────────────────────────

  group('Scenario 3 — Trickle ICE (addIceCandidate incremental)', () {
    SignalingServer? sigServer;
    HttpServer? htmlServer;
    int htmlPort = 0;
    WebDriverSession? driver;

    setUp(() async {
      sigServer = await SignalingServer.start();
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await createFirefoxSession();
    });

    tearDown(() async {
      await driver?.quit();
      await htmlServer?.close(force: true);
      await sigServer?.close();
    });

    test('ICE connection established via trickle candidates', () async {
      final d = driver!;
      final sig = sigServer!;

      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=answerer&scenario=trickle';
      await d.navigateTo(url);

      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      final offererFuture = _runWebdartcOfferer(sig.port);

      try {
        await waitFor(
          () async {
            final v = await browserState(d, 'iceState');
            return v == 'connected' || v == 'completed';
          },
          timeout: const Duration(seconds: 30),
        );
      } catch (e) {
        await _printBrowserLog(d);
        rethrow;
      }

      await waitFor(
        () async => await browserState(d, 'dcOpen') == true,
        timeout: const Duration(seconds: 30),
      );

      await offererFuture.timeout(const Duration(seconds: 30));
    });
  });

  // Scenario 4 (Firefox offerer ↔ webdartc echo) is skipped for the same
  // reason as Scenario 1b: Firefox sends STUN from non-candidate ports.

  // Network impairment (packet loss / delay) tests are skipped for Firefox.
  // Firefox sends ICE binding requests from ports that differ from its
  // advertised candidates, which breaks the UDP proxy's address tracking.
  // Chrome E2E tests already validate retransmission logic; Firefox tests
  // here validate browser interop for the core WebRTC data channel path.
}

// ── Browser log helper ───────────────────────────────────────────────────────

Future<void> _printBrowserLog(WebDriverSession driver) async {
  try {
    final logBuf = await driver.executeScript(
        'return document.getElementById("log").textContent.slice(-1000);');
    if (logBuf != null) {
      // ignore: avoid_print
      print('[firefox-log] ${(logBuf as String).replaceAll("\n", " | ")}');
    }
  } catch (_) {
    // ignore: avoid_print
    print('[firefox-log] could not read browser log');
  }
}

// ── webdartc helper launchers ────────────────────────────────────────────────

Future<void> _runWebdartcOfferer(int signalingPort,
    {int timeoutSec = 30}) async {
  final proc = await Process.start(
    Platform.resolvedExecutable,
    [
      'run',
      'test/e2e/webdartc_offerer_helper.dart',
      '--port=$signalingPort',
      '--timeout=$timeoutSec',
    ],
    environment: {...Platform.environment, 'WEBDARTC_DEBUG': '1'},
  );

  final stderrLines = <String>[];
  proc.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen(
        (line) {
          stderrLines.add(line);
          // ignore: avoid_print
          print('[offerer] $line');
        },
      );
  proc.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen(
        (line) => print('[offerer-stdout] $line'),
      );

  final exitCode = await proc.exitCode;
  if (exitCode != 0) {
    throw Exception(
      'webdartc offerer failed (exit $exitCode):\n'
      '${stderrLines.join('\n')}',
    );
  }
}
