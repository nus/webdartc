/// Bidirectional E2E: browser (fake camera) → Dart VT decoder.
///
/// The Dart sender runs with --bidir, which makes the transceiver
/// `sendrecv`. Chrome is launched with `--use-fake-device-for-media-stream`
/// so getUserMedia returns a canned green-bar video that the browser sends
/// back. We poll the sender's stdout for `[sender] decoded #N` lines to
/// verify the Dart-side decoder produced at least one frame.
@Tags(['e2e'])
@TestOn('mac-os')
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

  test('Dart sender decodes H.264 frames sent from browser fake camera',
      () async {
    final port = await _findFreePort();

    final server = await _spawnDart(
      'example/video_call/bin/server.dart',
      ['--port=$port'],
    );
    server.stdout.transform(utf8.decoder).listen((line) {
      // ignore: avoid_print
      stdout.write('[server] $line');
    });
    server.stderr.transform(utf8.decoder).listen((line) {
      // ignore: avoid_print
      stderr.write('[server-err] $line');
    });

    await waitFor(() async {
      try {
        final s = await Socket.connect('127.0.0.1', port,
            timeout: const Duration(milliseconds: 500));
        s.destroy();
        return true;
      } catch (_) {
        return false;
      }
    }, timeout: const Duration(seconds: 10));

    final cdp = await CdpBrowser.create(cft, extraArgs: const [
      '--use-fake-device-for-media-stream',
      '--use-fake-ui-for-media-stream',
      '--autoplay-policy=no-user-gesture-required',
    ]);
    await cdp.navigateTo('http://127.0.0.1:$port/?bidir=1');

    // Skip when the browser build lacks an H.264 encoder (e.g. Playwright's
    // Chromium). We rely on the browser sending H.264 RTP back to Dart.
    final codecsRaw = await cdp.executeScript(
      'const c = RTCRtpSender.getCapabilities("video").codecs; '
      'return c.map(x => x.mimeType).join(",");',
    );
    final codecList = (codecsRaw as String? ?? '').toLowerCase();
    if (!codecList.contains('video/h264')) {
      markTestSkipped('browser lacks H.264 encoder (codecs=$codecList)');
      await cdp.quit();
      server.kill();
      return;
    }

    final sender = await _spawnDart(
      'example/video_call/bin/sender.dart',
      ['--port=$port', '--codec=h264', '--bidir'],
    );
    final decodedController = StreamController<int>.broadcast();
    final decodedRe = RegExp(r'\[sender\] decoded #(\d+)');
    sender.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      // ignore: avoid_print
      print('[sender] $line');
      final m = decodedRe.firstMatch(line);
      if (m != null) decodedController.add(int.parse(m.group(1)!));
    });
    sender.stderr.transform(utf8.decoder).listen((line) {
      // ignore: avoid_print
      stderr.write('[sender-err] $line');
    });

    try {
      final first = await decodedController.stream
          .first
          .timeout(const Duration(seconds: 60));
      expect(first, greaterThan(0));
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
