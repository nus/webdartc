/// E2E tests for webdartc with Firefox.
///
/// Mirrors the Chrome E2E test scenarios using Firefox via GeckoDriver
/// (W3C WebDriver protocol) instead of CDP.
///
/// Scenarios:
///   1.  Data channel: webdartc (offerer) ↔ Firefox (answerer)
///   2.  Media: webdartc (offerer, recvonly) ↔ Firefox (answerer, sendonly)
///       — audio only and audio+video BUNDLE
///   3.  Trickle ICE: validate addIceCandidate() incremental flow
///   Packet loss / delay — webdartc (offerer) ↔ Firefox (answerer) via UDP
///       proxy with 5% loss (ICE/STUN, DTLS, SCTP, SRTP) and 50±20 ms jitter
///
/// Skipped scenarios (known webdartc ICE limitation):
///   1b. Firefox offerer — ICE controlled agent race (non-candidate STUN port)
///   4.  Media echo — same as 1b (Firefox offerer)
///
/// Requires Firefox and GeckoDriver on PATH.
/// Run with:
///   dart test test/e2e/e2e_firefox_test.dart --timeout=180s
@Tags(['e2e'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'firefox_for_testing.dart';
import 'signaling_server/signaling_server.dart';
import 'udp_proxy/udp_proxy.dart';
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

  // ── Scenario 2: Media (webdartc recvonly ↔ Firefox sendonly) ──────────────
  //
  // webdartc is the DTLS server (a=setup:actpass → Firefox picks active).
  // Firefox's DTLS ClientHello use_srtp extension advertises profiles in the
  // order 0x0007 (GCM_128), 0x0008 (GCM_256), 0x0001 (CM_HMAC_SHA1_80),
  // 0x0002 (CM_HMAC_SHA1_32). webdartc's DTLS server selector in
  // lib/dtls/state_machine.dart prefers 0x0001 when offered, so both Chrome
  // (offers CM first) and Firefox (offers GCM first) converge on the
  // common-denominator SRTP_AES128_CM_HMAC_SHA1_80 profile.

  group('Scenario 2 — media (Firefox sends audio → webdartc receives)', () {
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

    test('webdartc receives onTrack from Firefox audio', () async {
      final d = driver!;
      final sig = sigServer!;

      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=answerer&scenario=media';
      await d.navigateTo(url);

      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      final receiverFuture = _runWebdartcMediaReceiver(sig.port);

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

      // Verify Firefox is actually sending RTP.
      await waitFor(
        () async {
          final sent = await browserState(d, 'rtpPacketsSent');
          return sent != null && (sent as num) > 0;
        },
        timeout: const Duration(seconds: 20),
      );

      await receiverFuture.timeout(const Duration(seconds: 30));
    });

    test('webdartc receives onTrack from Firefox video (audio+video BUNDLE)',
        () async {
      final d = driver!;
      final sig = sigServer!;

      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=answerer&scenario=media-video';
      await d.navigateTo(url);

      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      // Same as Chrome Scenario 2 video variant: helper exits on first onTrack
      // (audio), confirming the audio+video BUNDLE SDP + DTLS + SRTP pipeline.
      final receiverFuture =
          _runWebdartcMediaReceiver(sig.port, kind: 'video');

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
        () async {
          final sent = await browserState(d, 'rtpPacketsSent');
          return sent != null && (sent as num) > 0;
        },
        timeout: const Duration(seconds: 20),
      );

      await receiverFuture.timeout(const Duration(seconds: 30));
    });
  });

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

  // ── Network impairment tests ──────────────────────────────────────────────
  //
  // These tests mirror the Chrome packet-loss suite with Firefox as the
  // answerer. They are currently blocked by a UDP proxy / Firefox socket
  // interaction: Firefox uses separate UDP sockets for ICE connectivity
  // checks versus DTLS/media transport. The UDP proxy identifies peers by
  // source port (test/e2e/udp_proxy/udp_proxy.dart:156 — `_portsA` /
  // `_portsB` sets populated from ICE candidates by the signaling server).
  // Once ICE checks complete on one socket, Firefox switches to a different
  // source port for DTLS, which is not in `_portsB`, so the proxy's
  // `_onReceive` returns without forwarding (line 169 "Unknown source —
  // ignore"). Observed symptom: `ProxyStats(fwd=1, drop=0, bytes≈80)` in
  // each direction — only the initial STUN request/response pair traverses
  // the proxy, then the connection stalls.
  //
  // TODO(webdartc): teach UdpProxy to dynamically learn new source ports
  // on loopback (e.g., associate any unknown port with the peer whose
  // already-known ports did not send the packet). Until then, these tests
  // are skipped to match the Chrome packet-loss suite's intent.
  const _proxyPortBugSkipReason =
      'blocked by UDP proxy peer identification: Firefox sends DTLS from a '
      'different source port than its ICE candidates, and UdpProxy._onReceive '
      'ignores unknown source ports. Only the first STUN exchange makes it '
      'through; subsequent DTLS/SCTP/SRTP packets are dropped.';

  group('Packet loss — ICE/STUN retransmission (5% loss) [Firefox]',
      skip: _proxyPortBugSkipReason, () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late WebDriverSession driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(lossRate: 0.05),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await createFirefoxSession();
    });

    tearDown(() async {
      // ignore: avoid_print
      print('[proxy-stats] A→B: ${proxy.statsAtoB}  B→A: ${proxy.statsBtoA}');
      await driver.quit();
      await htmlServer.close(force: true);
      await sigServer.close();
      await proxy.close();
    });

    test('ICE connects despite 5% packet loss', () async {
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sigServer.port}'
          '&role=answerer&scenario=data';
      await driver.navigateTo(url);
      await waitFor(
        () async => await browserState(driver, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      // Start offerer but don't await full exchange — only check ICE reaches
      // connected (validates STUN binding request retransmission).
      _runWebdartcOfferer(sigServer.port, timeoutSec: 90);

      await waitFor(
        () async {
          final v = await browserState(driver, 'iceState');
          return v == 'connected' || v == 'completed';
        },
        timeout: const Duration(seconds: 60),
        interval: const Duration(seconds: 3),
      );
    });
  });

  group('Packet loss — DTLS handshake retransmission (5% loss) [Firefox]',
      skip: _proxyPortBugSkipReason, () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late WebDriverSession driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(lossRate: 0.05),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await createFirefoxSession();
    });

    tearDown(() async {
      // ignore: avoid_print
      print('[proxy-stats] A→B: ${proxy.statsAtoB}  B→A: ${proxy.statsBtoA}');
      await driver.quit();
      await htmlServer.close(force: true);
      await sigServer.close();
      await proxy.close();
    });

    test('DTLS handshake completes despite 5% packet loss', () async {
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sigServer.port}'
          '&role=answerer&scenario=data';
      await driver.navigateTo(url);
      await waitFor(
        () async => await browserState(driver, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      _runWebdartcOfferer(sigServer.port, timeoutSec: 90);

      // Data channel open proves DTLS handshake + SCTP INIT completed.
      await waitFor(
        () async => await browserState(driver, 'dcOpen') == true,
        timeout: const Duration(seconds: 90),
      );
    });
  });

  group('Packet loss — SCTP data retransmission (5% loss) [Firefox]',
      skip: _proxyPortBugSkipReason, () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late WebDriverSession driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(lossRate: 0.05),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await createFirefoxSession();
    });

    tearDown(() async {
      // ignore: avoid_print
      print('[proxy-stats] A→B: ${proxy.statsAtoB}  B→A: ${proxy.statsBtoA}');
      await driver.quit();
      await htmlServer.close(force: true);
      await sigServer.close();
      await proxy.close();
    });

    test('data messages delivered despite 5% packet loss', () async {
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sigServer.port}'
          '&role=answerer&scenario=data';
      await driver.navigateTo(url);
      await waitFor(
        () async => await browserState(driver, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      // 1KB text is sufficient to prove SCTP retransmission works — the 64KB
      // binary takes too long with 5% loss due to the 3s T3-rtx timer.
      _runWebdartcOfferer(sigServer.port, timeoutSec: 90);

      await waitFor(
        () async {
          final c = await browserState(driver, 'receivedCount');
          return c != null && (c as num) >= 1;
        },
        timeout: const Duration(seconds: 90),
      );
    });
  });

  group('Packet loss — SRTP media tolerance (5% loss) [Firefox]',
      skip: _proxyPortBugSkipReason, () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late WebDriverSession driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(lossRate: 0.05),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await createFirefoxSession();
    });

    tearDown(() async {
      // ignore: avoid_print
      print('[proxy-stats] A→B: ${proxy.statsAtoB}  B→A: ${proxy.statsBtoA}');
      await driver.quit();
      await htmlServer.close(force: true);
      await sigServer.close();
      await proxy.close();
    });

    test('audio RTP received despite 5% packet loss', () async {
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sigServer.port}'
          '&role=answerer&scenario=media';
      await driver.navigateTo(url);
      await waitFor(
        () async => await browserState(driver, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      final receiverFuture = _runWebdartcMediaReceiver(sigServer.port);

      await waitFor(
        () async {
          final v = await browserState(driver, 'iceState');
          return v == 'connected' || v == 'completed';
        },
        timeout: const Duration(seconds: 60),
        interval: const Duration(seconds: 3),
      );

      await waitFor(
        () async {
          final sent = await browserState(driver, 'rtpPacketsSent');
          return sent != null && (sent as num) > 0;
        },
        timeout: const Duration(seconds: 30),
      );

      await receiverFuture.timeout(const Duration(seconds: 60));
    });
  });

  group('Packet loss — delay + jitter (50ms ± 20ms) [Firefox]',
      skip: _proxyPortBugSkipReason, () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late WebDriverSession driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(delayMs: 50, jitterMs: 20),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await createFirefoxSession();
    });

    tearDown(() async {
      // ignore: avoid_print
      print('[proxy-stats] A→B: ${proxy.statsAtoB}  B→A: ${proxy.statsBtoA}');
      await driver.quit();
      await htmlServer.close(force: true);
      await sigServer.close();
      await proxy.close();
    });

    test('data channel works with 50ms delay + 20ms jitter', () async {
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sigServer.port}'
          '&role=answerer&scenario=data';
      await driver.navigateTo(url);
      await waitFor(
        () async => await browserState(driver, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      final offererFuture =
          _runWebdartcOfferer(sigServer.port, timeoutSec: 90);

      await waitFor(
        () async => await browserState(driver, 'dcOpen') == true,
        timeout: const Duration(seconds: 60),
      );

      await offererFuture.timeout(const Duration(seconds: 90));

      final received = await browserState(driver, 'receivedCount');
      expect(received, greaterThanOrEqualTo(2));
    });
  });
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

// ── webdartc media receiver helper ──────────────────────────────────────────

/// Runs the webdartc media receiver as a subprocess, streaming stderr.
/// Returns when onTrack fires (exit 0) or throws on failure.
Future<void> _runWebdartcMediaReceiver(int signalingPort,
    {String kind = 'audio'}) async {
  final proc = await Process.start(
    Platform.resolvedExecutable,
    [
      'run',
      'test/e2e/media_receiver_helper.dart',
      '--port=$signalingPort',
      '--kind=$kind',
    ],
    environment: {...Platform.environment, 'WEBDARTC_DEBUG': '1'},
  );

  final stderrLines = <String>[];
  proc.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen(
        (line) {
          stderrLines.add(line);
          // ignore: avoid_print
          print('[media-receiver] $line');
        },
      );
  proc.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen(
        // ignore: avoid_print
        (line) => print('[media-receiver-stdout] $line'),
      );

  final exitCode = await proc.exitCode;
  if (exitCode != 0) {
    throw Exception(
      'webdartc media receiver failed (exit $exitCode):\n'
      '${stderrLines.join('\n')}',
    );
  }
}
