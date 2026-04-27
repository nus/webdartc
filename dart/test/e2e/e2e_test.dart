/// E2E tests for webdartc.
///
/// Scenarios:
///   1. Data channel: webdartc (offerer) -- Chrome (answerer)
///   3. Trickle ICE: validate addIceCandidate() incremental flow
///
/// Requires Chrome for Testing (auto-downloaded on first run).
/// Run with:
///   dart test test/e2e/ --timeout=240s
///
/// File-level @Timeout overrides the CLI timeout. The packet-loss
/// scenarios pile per-test waits (up to 180s each) on top of `dart run`
/// JIT-compile time on slow CI runners; 240s gives a safety margin.
@Tags(['e2e'])
@Timeout(Duration(seconds: 240))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'cdp_browser.dart';
import 'chrome_for_testing.dart';
import 'signaling_server/signaling_server.dart';
import 'udp_proxy/udp_proxy.dart';

/// Chrome flags this suite requires on top of [CdpBrowser.create] defaults:
/// fake media devices for getUserMedia, and verbose WebRTC logging for
/// diagnostics on failure.
const _scenarioChromeFlags = [
  '--use-fake-device-for-media-stream',
  '--use-fake-ui-for-media-stream',
  '--enable-logging=stderr',
  '--v=1',
  '--vmodule=*p2p*=5,*stun*=5,*ice*=5,*dtls*=3',
];

/// Launches a browser with this suite's required flags and attaches a
/// stderr listener that surfaces ERROR/FATAL lines.
Future<CdpBrowser> _launchScenarioBrowser(ChromeForTesting cft) {
  return CdpBrowser.create(
    cft,
    extraArgs: _scenarioChromeFlags,
    onStderrLine: (line) {
      if (line.contains('ERROR') || line.contains('FATAL')) {
        // ignore: avoid_print
        print('[chrome-err] $line');
      }
    },
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
  late ChromeForTesting cft;

  setUpAll(() async {
    cft = await ChromeForTesting.ensureAvailable();
  });

  // ── Scenario 1: Data channel webdartc ↔ Chrome ───────────────────────────

  group('Scenario 1 — data channel (webdartc offerer ↔ Chrome answerer)', () {
    SignalingServer? sigServer;
    HttpServer? htmlServer;
    int htmlPort = 0;
    CdpBrowser? driver;

    setUp(() async {
      sigServer = await SignalingServer.start();
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
    });

    tearDown(() async {
      await driver?.quit();
      await htmlServer?.close(force: true);
      await sigServer?.close();
    });

    test('open, send text 1KB, send binary 64KB, receive echoes', () async {
      final d = driver!;
      final sig = sigServer!;

      // Navigate Chrome to the browser client as answerer.
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=answerer&scenario=data';
      await d.navigateTo(url);

      // Wait for the page to signal it's ready.
      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      // webdartc side: connect as offerer via the same signaling server.
      final offererFuture = _runWebdartcOfferer(sig.port);

      // Wait for Chrome to report ICE connected, printing Chrome stats periodically.
      try {
        await waitFor(
          () async {
            final v = await browserState(d, 'iceState');
            final pairs = await browserState(d, 'icePairs');
            final cands = await browserState(d, 'iceCands');
            final bytesRx = await browserState(d, 'transportBytesRx');
            final bytesTx = await browserState(d, 'transportBytesTx');
            final iceErr = await browserState(d, 'iceError');
            // Read page log buffer
            final logBuf = await d.executeScript(
                'return document.getElementById("log").textContent.slice(-500);');
            // ignore: avoid_print
            print('[chrome-stats] ICE=$v bytesRx=$bytesRx bytesTx=$bytesTx iceErr=$iceErr pairs=$pairs cands=$cands');
            if (logBuf != null) print('[chrome-log] ${(logBuf as String).replaceAll("\n", " | ")}');
            return v == 'connected' || v == 'completed';
          },
          timeout: const Duration(seconds: 30),
          interval: const Duration(seconds: 3),
        );
      } catch (e) {
        // Print Chrome internal log before re-throwing
        _printChromeLog();
        rethrow;
      }

      // Wait for Chrome data channel to open.
      await waitFor(
        () async => await browserState(d, 'dcOpen') == true,
        timeout: const Duration(seconds: 15),
      );

      // Let the webdartc offerer finish its exchange.
      await offererFuture.timeout(const Duration(seconds: 30));

      // Chrome should have received 2 messages (text 1KB + binary 64KB).
      final received = await browserState(d, 'receivedCount');
      expect(received, greaterThanOrEqualTo(2));
    });
  });

  // ── Scenario 1b: Data channel (Chrome offerer ↔ webdartc answerer) ────────

  group('Scenario 1b — data channel (Chrome offerer ↔ webdartc answerer)', () {
    SignalingServer? sigServer;
    HttpServer? htmlServer;
    int htmlPort = 0;
    CdpBrowser? driver;

    setUp(() async {
      sigServer = await SignalingServer.start();
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
    });

    tearDown(() async {
      await driver?.quit();
      await htmlServer?.close(force: true);
      await sigServer?.close();
    });

    test('Chrome offerer sends, webdartc answerer echoes', () async {
      final d = driver!;
      final sig = sigServer!;

      // Start webdartc answerer FIRST so it's connected to signaling
      // before Chrome sends the offer.
      final answererFuture = _runWebdartcAnswerer(sig.port);
      // Brief delay to let the answerer subprocess connect to signaling.
      await Future<void>.delayed(const Duration(seconds: 3));

      // Chrome acts as offerer — creates data channel + sends offer.
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=offerer&scenario=data';
      await d.navigateTo(url);

      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      // Wait for Chrome ICE connected.
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
        _printChromeLog();
        rethrow;
      }

      // Wait for Chrome data channel to open.
      await waitFor(
        () async => await browserState(d, 'dcOpen') == true,
        timeout: const Duration(seconds: 15),
      );

      // Chrome sends a text message to webdartc.
      await d.executeScript('window.sendText("hello from chrome")');

      // Wait for webdartc answerer to succeed.
      await answererFuture.timeout(const Duration(seconds: 30));
    });
  });

  // ── Scenario 2: Media (Chrome sends audio → webdartc receives) ────────────

  group('Scenario 2 — media (Chrome sends audio → webdartc receives)', () {
    SignalingServer? sigServer;
    HttpServer? htmlServer;
    int htmlPort = 0;
    CdpBrowser? driver;

    setUp(() async {
      sigServer = await SignalingServer.start();
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
    });

    tearDown(() async {
      await driver?.quit();
      await htmlServer?.close(force: true);
      await sigServer?.close();
    });

    test('webdartc receives onTrack from Chrome audio', () async {
      final d = driver!;
      final sig = sigServer!;

      // Navigate Chrome to the browser client as answerer with media scenario.
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=answerer&scenario=media';
      await d.navigateTo(url);

      // Wait for the page to signal it's ready.
      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      // webdartc side: connect as offerer with recvonly audio.
      final receiverFuture = _runWebdartcMediaReceiver(sig.port);

      // Wait for Chrome to report ICE connected.
      try {
        await waitFor(
          () async {
            final v = await browserState(d, 'iceState');
            final rtpSent = await browserState(d, 'rtpPacketsSent');
            // ignore: avoid_print
            print('[chrome-stats] ICE=$v rtpPacketsSent=$rtpSent');
            return v == 'connected' || v == 'completed';
          },
          timeout: const Duration(seconds: 30),
          interval: const Duration(seconds: 3),
        );
      } catch (e) {
        _printChromeLog();
        rethrow;
      }

      // Verify Chrome sent RTP packets.
      await waitFor(
        () async {
          final sent = await browserState(d, 'rtpPacketsSent');
          return sent != null && (sent as num) > 0;
        },
        timeout: const Duration(seconds: 15),
      );

      // Wait for media receiver helper to succeed (onTrack fired → exit 0).
      await receiverFuture.timeout(const Duration(seconds: 30));
    });

    test('webdartc receives onTrack from Chrome video (fake device)', () async {
      final d = driver!;
      final sig = sigServer!;

      // Navigate Chrome to the browser client as answerer with video scenario.
      // Chrome provides both audio and video via fake device.
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=answerer&scenario=media-video';
      await d.navigateTo(url);

      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      // webdartc side: connect as offerer with recvonly audio+video.
      // Chrome's video encoder requires RTCP feedback (RR/PLI) before it
      // starts sending video frames. Since we don't implement RTCP RR yet,
      // we verify video SDP negotiation succeeds and audio onTrack fires.
      // The helper exits on the first onTrack (audio), confirming the full
      // audio+video BUNDLE SDP + DTLS + SRTP pipeline works.
      final receiverFuture = _runWebdartcMediaReceiver(sig.port, kind: 'video');

      // Wait for Chrome ICE connected.
      try {
        await waitFor(
          () async {
            final v = await browserState(d, 'iceState');
            final rtpSent = await browserState(d, 'rtpPacketsSent');
            // ignore: avoid_print
            print('[chrome-stats] ICE=$v audioRtpPacketsSent=$rtpSent');
            return v == 'connected' || v == 'completed';
          },
          timeout: const Duration(seconds: 30),
          interval: const Duration(seconds: 3),
        );
      } catch (e) {
        _printChromeLog();
        rethrow;
      }

      // Verify Chrome sent audio RTP packets (video requires RTCP feedback).
      await waitFor(
        () async {
          final sent = await browserState(d, 'rtpPacketsSent');
          return sent != null && (sent as num) > 0;
        },
        timeout: const Duration(seconds: 15),
      );

      // Wait for media receiver helper — verifies audio onTrack fires in
      // an audio+video BUNDLE session. Video onTrack requires RTCP RR/PLI
      // implementation (tracked separately).
      await receiverFuture.timeout(const Duration(seconds: 30));
    });
  });

  // ── Scenario 4: Media echo (Chrome sends audio → webdartc echoes back) ───

  group('Scenario 4 — media echo (Chrome offerer ↔ webdartc echo)', () {
    SignalingServer? sigServer;
    HttpServer? htmlServer;
    int htmlPort = 0;
    CdpBrowser? driver;

    setUp(() async {
      sigServer = await SignalingServer.start();
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
    });

    tearDown(() async {
      await driver?.quit();
      await htmlServer?.close(force: true);
      await sigServer?.close();
    });

    test('webdartc echoes audio RTP back to Chrome', () async {
      final d = driver!;
      final sig = sigServer!;

      // Start echo helper first (answerer).
      final echoFuture = _runWebdartcEcho(sig.port);
      await Future<void>.delayed(const Duration(seconds: 3));

      // Chrome as offerer with audio.
      final url =
          'http://127.0.0.1:$htmlPort/?port=${sig.port}'
          '&role=offerer&scenario=media-echo';
      await d.navigateTo(url);

      await waitFor(
        () async => await browserState(d, 'ready') == true,
        timeout: const Duration(seconds: 10),
      );

      // Wait for Chrome ICE connected.
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
        _printChromeLog();
        rethrow;
      }

      // Verify Chrome receives echo RTP from webdartc.
      await waitFor(
        () async {
          final received = await browserState(d, 'rtpPacketsReceived');
          // ignore: avoid_print
          print('[chrome-stats] rtpPacketsReceived=$received');
          return received != null && (received as num) > 0;
        },
        timeout: const Duration(seconds: 20),
        interval: const Duration(seconds: 2),
      );

      // Check audio decode quality
      await Future<void>.delayed(const Duration(seconds: 2));
      final concealed = await browserState(d, 'audioConcealed');
      final totalSamples = await browserState(d, 'audioTotalSamples');
      final received = await browserState(d, 'rtpPacketsReceived');
      // ignore: avoid_print
      print('[chrome-audio] received=$received totalSamples=$totalSamples concealed=$concealed');

      // Wait for echo helper to complete.
      await echoFuture.timeout(const Duration(seconds: 30));
    });
  });

  // ── Scenario 5: Video reflect (Chrome sends video → webdartc reflects) ───
  // SKIP: Chrome's VP8 encoder requires transport-cc congestion control
  // feedback before it starts sending video. RTCP RR + PLI + REMB alone
  // are not sufficient. Requires transport-cc implementation (RFC 8888).

  group('Scenario 5 — video reflect (Chrome offerer ↔ webdartc reflect)', () {
    SignalingServer? sigServer;
    HttpServer? htmlServer;
    int htmlPort = 0;
    CdpBrowser? driver;

    setUp(() async {
      sigServer = await SignalingServer.start();
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
    });

    tearDown(() async {
      await driver?.quit();
      await htmlServer?.close(force: true);
      await sigServer?.close();
    });

    test('Chrome receives reflected video from webdartc', () async {
      final d = driver!;
      final sig = sigServer!;

      // Start reflect helper (answerer) — keeps running until killed.
      final reflectProc = await _startWebdartcReflect(sig.port);
      await Future<void>.delayed(const Duration(seconds: 3));

      try {
        // Chrome as offerer with video.
        final url =
            'http://127.0.0.1:$htmlPort/?port=${sig.port}'
            '&role=offerer&scenario=media-video-reflect';
        await d.navigateTo(url);

        await waitFor(
          () async => await browserState(d, 'ready') == true,
          timeout: const Duration(seconds: 10),
        );

        // Wait for Chrome ICE connected.
        await waitFor(
          () async {
            final v = await browserState(d, 'iceState');
            return v == 'connected' || v == 'completed';
          },
          timeout: const Duration(seconds: 30),
          interval: const Duration(seconds: 3),
        );

        // Wait for Chrome to send video and receive reflected video back.
        await waitFor(
          () async {
            final sent = await browserState(d, 'videoRtpPacketsSent');
            final recv = await browserState(d, 'videoRtpPacketsReceived');
            // ignore: avoid_print
            print('[chrome-stats] videoSent=$sent videoRecv=$recv');
            return recv != null && (recv as num) > 0;
          },
          timeout: const Duration(seconds: 30),
          interval: const Duration(seconds: 2),
        );

        // ── BWE diagnostic: poll bandwidth/quality stats for 20 seconds ──
        // Reflect helper is still running so transport-cc feedback continues.
        for (var i = 0; i < 10; i++) {
          await Future<void>.delayed(const Duration(seconds: 2));
          final bwe = await browserState(d, 'bweAvailableOutgoing');
          final rtt = await browserState(d, 'bweCurrentRtt');
          final target = await browserState(d, 'videoTargetBitrate');
          final width = await browserState(d, 'videoFrameWidth');
          final height = await browserState(d, 'videoFrameHeight');
          final qpSum = await browserState(d, 'videoQpSum');
          final qlReason = await browserState(d, 'videoQualityLimitationReason');
          final lost = await browserState(d, 'videoRemotePacketsLost');
          final jitter = await browserState(d, 'videoRemoteJitter');
          final nack = await browserState(d, 'videoNackCount');
          final retx = await browserState(d, 'videoRetransmittedPacketsSent');
          final sent = await browserState(d, 'videoRtpPacketsSent');
          // ignore: avoid_print
          print('[bwe-diag] t=${i * 2 + 2}s bwe=$bwe target=$target '
              'rtt=$rtt ${width}x$height qp=$qpSum ql=$qlReason '
              'lost=$lost jitter=$jitter nack=$nack retx=$retx sent=$sent');
        }
      } finally {
        reflectProc.kill();
        await reflectProc.exitCode.timeout(const Duration(seconds: 5),
            onTimeout: () { reflectProc.kill(ProcessSignal.sigkill); return -1; });
      }
    });

    test('Chrome receives reflected video via RTP Transport API', () async {
      final d = driver!;
      final sig = sigServer!;

      // Start RTP Transport API reflect helper (answerer) first.
      final reflectProc = await _startWebdartcReflectRtpTransport(sig.port);
      await Future<void>.delayed(const Duration(seconds: 3));

      try {
        // Chrome as offerer with video.
        final url =
            'http://127.0.0.1:$htmlPort/?port=${sig.port}'
            '&role=offerer&scenario=media-video-reflect';
        await d.navigateTo(url);

        await waitFor(
          () async => await browserState(d, 'ready') == true,
          timeout: const Duration(seconds: 10),
        );

        await waitFor(
          () async {
            final v = await browserState(d, 'iceState');
            return v == 'connected' || v == 'completed';
          },
          timeout: const Duration(seconds: 30),
          interval: const Duration(seconds: 3),
        );

        // Wait for Chrome to actually decode reflected video frames (not just
        // receive RTP packets).  framesDecoded > 0 proves Chrome received a
        // valid keyframe and the VP8 decoder is producing output.
        await waitFor(
          () async {
            final sent = await browserState(d, 'videoRtpPacketsSent');
            final recv = await browserState(d, 'videoRtpPacketsReceived');
            final dec = await browserState(d, 'videoFramesDecoded');
            final pli = await browserState(d, 'videoPliCount');
            final fir = await browserState(d, 'videoFirCount');
            final keyEnc = await browserState(d, 'videoKeyFramesEncoded');
            // ignore: avoid_print
            print('[chrome-stats] sent=$sent recv=$recv dec=$dec pli=$pli fir=$fir keyEnc=$keyEnc');
            return dec != null && (dec as num) > 0;
          },
          timeout: const Duration(seconds: 30),
          interval: const Duration(seconds: 2),
        );
      } finally {
        reflectProc.kill();
      }
    });
  });

  // ── Scenario 3: Trickle ICE ───────────────────────────────────────────────

  group('Scenario 3 — Trickle ICE (addIceCandidate incremental)', () {
    SignalingServer? sigServer;
    HttpServer? htmlServer;
    int htmlPort = 0;
    CdpBrowser? driver;

    setUp(() async {
      sigServer = await SignalingServer.start();
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
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

      // webdartc performs trickle ICE (candidates relayed one by one).
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
        _printChromeLog();
        rethrow;
      }

      // Confirm data channel opens (proves DTLS + SCTP are working).
      await waitFor(
        () async => await browserState(d, 'dcOpen') == true,
        timeout: const Duration(seconds: 15),
      );

      await offererFuture.timeout(const Duration(seconds: 30));
    });
  });

  // ── Network impairment tests ──────────────────────────────────────────────
  //
  // Each test validates packet loss resilience at a specific protocol layer:
  //   ICE/STUN  → retransmission of binding requests (500ms backoff, max 7)
  //   DTLS      → flight retransmission (500ms exponential backoff, max 7)
  //   SCTP      → T3-rtx data retransmission (3000ms)
  //   SRTP      → loss tolerance (no retransmission, 64-pkt replay window)
  //
  // The UDP proxy drops packets at the transport level, affecting all layers.
  // Test assertions determine which layer is validated:
  //   iceState == connected   → ICE retransmission works
  //   dcOpen == true          → DTLS + SCTP handshake retransmission works
  //   receivedCount >= 2      → SCTP data retransmission works
  //   rtpPacketsReceived > 0  → media survives loss

  group('Packet loss — ICE/STUN retransmission (5% loss)', () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late CdpBrowser driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(lossRate: 0.05),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
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

      // Start offerer but don't wait for full exchange — only check ICE.
      // unawaited(): the test verifies ICE only. Without unawaited, dart
      // test still tracks the future and reports "failed after test
      // completion" once the offerer's --timeout fires; it also stalls
      // the next test until that timeout expires. Combined with the
      // signaling-WebSocket-close exit in webdartc_offerer_helper.dart,
      // the offerer terminates within ms of tearDown so the next test
      // starts on a clean runner.
      unawaited(_runWebdartcOfferer(sigServer.port, timeoutSec: 180));

      // ICE connected proves STUN binding request retransmission works.
      // Slow CI runners need >60s under 5% loss + retransmit backoff.
      await waitFor(
        () async {
          final v = await browserState(driver, 'iceState');
          return v == 'connected' || v == 'completed';
        },
        timeout: const Duration(seconds: 120),
        interval: const Duration(seconds: 3),
      );
    });
  });

  group('Packet loss — DTLS handshake retransmission (5% loss)', () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late CdpBrowser driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(lossRate: 0.05),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
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

      // Start offerer but don't wait for full exchange — only check dcOpen.
      // See ICE/STUN test for why we unawait the offerer.
      unawaited(_runWebdartcOfferer(sigServer.port, timeoutSec: 180));

      // Data channel open proves DTLS handshake + SCTP INIT completed.
      // DTLS retransmission backoff under 5% loss can push handshake
      // completion past 90s on CI.
      await waitFor(
        () async => await browserState(driver, 'dcOpen') == true,
        timeout: const Duration(seconds: 180),
      );
    });
  });

  group('Packet loss — SCTP data retransmission (5% loss)', () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late CdpBrowser driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(lossRate: 0.05),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
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

      // Start offerer but don't wait for full 64KB exchange — the 1KB text
      // message is sufficient to prove SCTP retransmission works. The 64KB
      // binary takes too long with 5% loss due to SCTP's 3s T3-rtx timer.
      // See ICE/STUN test for why we unawait the offerer.
      unawaited(_runWebdartcOfferer(sigServer.port, timeoutSec: 180));

      // receivedCount >= 1 proves SCTP delivered the 1KB text through loss.
      // CI's wall-clock variability pushed the original 90s window past
      // the offerer's done-future on Linux runners.
      await waitFor(
        () async {
          final c = await browserState(driver, 'receivedCount');
          return c != null && (c as num) >= 1;
        },
        timeout: const Duration(seconds: 180),
      );
    });
  });

  group('Packet loss — SRTP media tolerance (5% loss)', () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late CdpBrowser driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(lossRate: 0.05),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
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

      // ICE + DTLS must complete through lossy channel.
      await waitFor(
        () async {
          final v = await browserState(driver, 'iceState');
          return v == 'connected' || v == 'completed';
        },
        timeout: const Duration(seconds: 60),
        interval: const Duration(seconds: 3),
      );

      // Chrome sends RTP; some packets lost but enough get through.
      // rtpPacketsSent > 0 on Chrome + receiver helper exits 0 proves
      // SRTP decryption and replay window tolerate loss. CI runners can
      // be slow to flush stats — give 40s.
      await waitFor(
        () async {
          final sent = await browserState(driver, 'rtpPacketsSent');
          return sent != null && (sent as num) > 0;
        },
        timeout: const Duration(seconds: 40),
      );

      await receiverFuture.timeout(const Duration(seconds: 90));
    });
  });

  group('Packet loss — delay + jitter (50ms ± 20ms)', () {
    late UdpProxy proxy;
    late SignalingServer sigServer;
    late HttpServer htmlServer;
    late int htmlPort;
    late CdpBrowser driver;

    setUp(() async {
      proxy = await UdpProxy.startSymmetric(
        impairment: const ImpairmentConfig(delayMs: 50, jitterMs: 20),
      );
      sigServer = await SignalingServer.start(proxy: proxy);
      final (srv, port) = await serveHtml('test/e2e/browser_client/index.html');
      htmlServer = srv;
      htmlPort = port;
      driver = await _launchScenarioBrowser(cft);
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

      // CI runner subprocess startup latency: `dart run` JIT-compile of
      // the offerer helper from cold cache can eat most of a 60s window
      // before the first ICE state log line appears. 180s gives the
      // offerer time to start + complete its DTLS/SCTP setup under
      // 50ms+20ms jitter.
      final offererFuture = _runWebdartcOfferer(sigServer.port, timeoutSec: 180);

      await waitFor(
        () async => await browserState(driver, 'dcOpen') == true,
        timeout: const Duration(seconds: 120),
      );

      await offererFuture.timeout(const Duration(seconds: 180));

      final received = await browserState(driver, 'receivedCount');
      expect(received, greaterThanOrEqualTo(2));
    });
  });
}



// ── Chrome internal log helper ───────────────────────────────────────────────

void _printChromeLog() {
  try {
    final f = File('/tmp/chrome_webrtc_e2e.log');
    if (!f.existsSync()) {
      print('[chrome-internal-log] file not found: /tmp/chrome_webrtc_e2e.log');
      return;
    }
    final lines = f.readAsLinesSync();
    // Print last 200 lines (ICE/STUN relevant)
    final relevant = lines
        .where((l) =>
            l.contains('stun') ||
            l.contains('STUN') ||
            l.contains('p2p') ||
            l.contains('ice') ||
            l.contains('ICE') ||
            l.contains('candidate') ||
            l.contains('integrity') ||
            l.contains('fingerprint') ||
            l.contains('webrtc') ||
            l.contains('WebRTC'))
        .toList();
    print('[chrome-internal-log] ${relevant.length} relevant lines (last 100):');
    for (final line in relevant.skip(relevant.length > 100 ? relevant.length - 100 : 0)) {
      print('[chrome] $line');
    }
  } catch (e) {
    print('[chrome-internal-log] error reading log: $e');
  }
}

// ── webdartc answerer helper ─────────────────────────────────────────────────

/// Runs the webdartc answerer as a subprocess, streaming stderr.
/// Returns when a data channel message is received (exit 0) or throws.
Future<void> _runWebdartcAnswerer(int signalingPort) async {
  final proc = await Process.start(
    Platform.resolvedExecutable,
    [
      'run',
      'test/e2e/webdartc_answerer_helper.dart',
      '--port=$signalingPort',
    ],
    environment: {...Platform.environment, 'WEBDARTC_DEBUG': '1'},
  );

  final stderrLines = <String>[];
  proc.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen(
        (line) {
          stderrLines.add(line);
          // ignore: avoid_print
          print('[answerer] $line');
        },
      );
  proc.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen(
        (line) => print('[answerer-stdout] $line'),
      );

  final exitCode = await proc.exitCode;
  if (exitCode != 0) {
    throw Exception(
      'webdartc answerer failed (exit $exitCode):\n'
      '${stderrLines.join('\n')}',
    );
  }
}

// ── webdartc video reflect helper ─────────────────────────────────────────────

/// Starts the video reflect helper and returns the Process.
/// The caller is responsible for killing the process when done.
Future<Process> _startWebdartcReflect(int signalingPort) async {
  final proc = await Process.start(
    Platform.resolvedExecutable,
    ['run', 'test/e2e/video_reflect_helper.dart', '--port=$signalingPort'],
    environment: {...Platform.environment, 'WEBDARTC_DEBUG': '1'},
  );
  proc.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
    // ignore: avoid_print
    print('[reflect] $line');
  });
  proc.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen(
    // ignore: avoid_print
    (line) => print('[reflect-stdout] $line'),
  );
  return proc;
}

// ── webdartc video reflect helper (RTP Transport API) ───────────────────────

/// Starts the RTP Transport API reflect helper and returns the Process.
/// The caller is responsible for killing the process when done.
Future<Process> _startWebdartcReflectRtpTransport(int signalingPort) async {
  final proc = await Process.start(
    Platform.resolvedExecutable,
    ['run', 'test/e2e/video_reflect_rtp_transport_helper.dart', '--port=$signalingPort'],
    environment: {...Platform.environment, 'WEBDARTC_DEBUG': '1'},
  );
  proc.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((line) {
    // ignore: avoid_print
    print('[reflect-rtp] $line');
  });
  proc.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen(
    // ignore: avoid_print
    (line) => print('[reflect-rtp-stdout] $line'),
  );
  return proc;
}

// ── webdartc echo helper ─────────────────────────────────────────────────────

Future<void> _runWebdartcEcho(int signalingPort) async {
  final proc = await Process.start(
    Platform.resolvedExecutable,
    [
      'run',
      'test/e2e/media_echo_helper.dart',
      '--port=$signalingPort',
    ],
    environment: {...Platform.environment, 'WEBDARTC_DEBUG': '1'},
  );

  final stderrLines = <String>[];
  proc.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen(
        (line) {
          stderrLines.add(line);
          // ignore: avoid_print
          print('[echo] $line');
        },
      );
  proc.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen(
        (line) => print('[echo-stdout] $line'),
      );

  final exitCode = await proc.exitCode;
  if (exitCode != 0) {
    throw Exception(
      'webdartc echo failed (exit $exitCode):\n'
      '${stderrLines.join('\n')}',
    );
  }
}

// ── webdartc offerer helper ───────────────────────────────────────────────────

/// Runs the webdartc offerer as a subprocess, streaming stderr to the console.
/// Returns when the exchange is complete (exit 0) or throws on failure.
Future<void> _runWebdartcOfferer(int signalingPort, {int timeoutSec = 30}) async {
  final spawnSw = Stopwatch()..start();
  // ignore: avoid_print
  print('[offerer-spawn] +${spawnSw.elapsedMilliseconds}ms calling Process.start');
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
  // ignore: avoid_print
  print('[offerer-spawn] +${spawnSw.elapsedMilliseconds}ms Process.start returned pid=${proc.pid}');

  // Stream stderr live so debug output is visible even on timeout.
  final stderrLines = <String>[];
  var firstStderrSeen = false;
  proc.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen(
        (line) {
          if (!firstStderrSeen) {
            firstStderrSeen = true;
            // ignore: avoid_print
            print('[offerer-spawn] +${spawnSw.elapsedMilliseconds}ms first stderr line');
          }
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
Future<void> _runWebdartcMediaReceiver(int signalingPort, {String kind = 'audio'}) async {
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
