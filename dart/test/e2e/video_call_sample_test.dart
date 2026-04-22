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

import 'cdp_browser.dart';
import 'chrome_for_testing.dart';

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

void main() {
  late ChromeForTesting cft;

  setUpAll(() async {
    cft = await ChromeForTesting.ensureAvailable();
  });

  for (final codec in ['vp8', 'h264']) {
    test('browser decodes $codec video frames from Dart sender', () async {
      if (codec == 'vp8' && Platform.isMacOS) {
        markTestSkipped('VP8 not supported on macOS (no libvpx); '
            'VideoToolbox covers H.264');
        return;
      }
      final port = await _findFreePort();

      // 1. Start the sample server.
      final server = await _spawnDart(
        'example/video_call/bin/server.dart',
        ['--port=$port'],
      );
      server.stdout.transform(utf8.decoder).listen((line) {
        // ignore: avoid_print
        print('[server] $line');
      });
      server.stderr.transform(utf8.decoder).listen((line) {
        // ignore: avoid_print
        print('[server-err] $line');
      });

      await waitFor(
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
      final cdp = await CdpBrowser.create(cft);
      await cdp.navigateTo('http://127.0.0.1:$port/');

      // Skip if the browser build lacks a decoder for the requested codec
      // (e.g. Playwright's Chromium build has no H.264 decoder).
      final codecsRaw = await cdp.executeScript(
        'const c = RTCRtpReceiver.getCapabilities("video").codecs; '
        'return c.map(x => x.mimeType).join(",");',
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
        await waitFor(
          () async {
            final decoded =
                await browserState(cdp, 'videoFramesDecoded') ?? 0;
            final ice = await browserState(cdp, 'iceState') ?? '';
            // ignore: avoid_print
            print('[test] ice=$ice framesDecoded=$decoded');
            final n = decoded is num ? decoded.toInt() : 0;
            return n > 0;
          },
          timeout: const Duration(seconds: 60),
          interval: const Duration(seconds: 2),
        );

        final finalDecoded =
            await browserState(cdp, 'videoFramesDecoded') ?? 0;
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
