/// Full browser ↔ Flutter bidirectional video E2E.
///
/// Spawns:
///   1. example/video_call/bin/server.dart (signaling + web server)
///   2. Chrome with a fake camera, pointed at /?bidir=1
///   3. The built Flutter macOS example app, configured via
///      WEBDARTC_PORT to connect to the same signaling server
///
/// Asserts:
///   - Chrome's inbound-rtp reports framesDecoded > 0
///     (Flutter → browser H.264 via VideoToolbox encode + RTP)
///   - Flutter app stdout reports decoded frames from the browser
///     (browser → Flutter H.264 via RTP + VideoToolbox decode +
///      ShaderVideoRenderer)
///
/// The Flutter app binary must be built beforehand (`flutter build
/// macos --debug` inside flutter/example/). CI wires this in the
/// `flutter-example-macos-bidir` job.
@Tags(['e2e'])
@TestOn('mac-os')
@Timeout(Duration(seconds: 180))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'cdp_browser.dart';
import 'chrome_for_testing.dart';

const _flutterAppPath =
    '../flutter/example/build/macos/Build/Products/Debug/'
    'webdartc_flutter_example.app/Contents/MacOS/'
    'webdartc_flutter_example';

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
  test('browser ↔ Flutter bidirectional H.264 video', () async {
    final appFile = File(_flutterAppPath);
    if (!appFile.existsSync()) {
      markTestSkipped(
          'Flutter example not built at $_flutterAppPath — '
          'run `flutter build macos --debug` in flutter/example/ first');
      return;
    }

    final cft = await ChromeForTesting.ensureAvailable();
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

    // Skip if the browser build cannot handle H.264 either direction.
    final capsRaw = await cdp.executeScript(
      'const s = RTCRtpSender.getCapabilities("video").codecs; '
      'const r = RTCRtpReceiver.getCapabilities("video").codecs; '
      'return (s.map(x=>x.mimeType).join(",")+"|"+r.map(x=>x.mimeType).join(",")).toLowerCase();',
    );
    final caps = (capsRaw as String? ?? '');
    if (!caps.contains('video/h264')) {
      markTestSkipped('browser lacks H.264 (caps=$caps)');
      await cdp.quit();
      server.kill();
      return;
    }

    final flutterApp = await Process.start(
      _flutterAppPath,
      const [],
      environment: {'WEBDARTC_PORT': '$port'},
    );
    final flutterRecv = StreamController<int>.broadcast();
    final flutterSent = StreamController<int>.broadcast();
    final recvRe = RegExp(r'\[flutter\] recv=(\d+)');
    final sentRe = RegExp(r'\[flutter\] sent=(\d+)');
    flutterApp.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      // ignore: avoid_print
      print('[flutter] $line');
      final mr = recvRe.firstMatch(line);
      if (mr != null) flutterRecv.add(int.parse(mr.group(1)!));
      final ms = sentRe.firstMatch(line);
      if (ms != null) flutterSent.add(int.parse(ms.group(1)!));
    });
    flutterApp.stderr.transform(utf8.decoder).listen((line) {
      // ignore: avoid_print
      stderr.write('[flutter-err] $line');
    });

    // The browser page installs its own getStats poller into
    // window.__testState; we just read from it. Injecting our own
    // snapshotter via Runtime.evaluate would fail because `pc` lives in
    // the page's module scope.
    try {
      // (a) Flutter → browser
      await waitFor(() async {
        final fd = await browserState(cdp, 'videoFramesDecoded') ?? 0;
        return (fd is num ? fd.toInt() : 0) > 0;
      }, timeout: const Duration(seconds: 60));

      // (b) browser → Flutter
      final first =
          await flutterRecv.stream.first.timeout(const Duration(seconds: 60));
      expect(first, greaterThan(0));

      final browserDecoded =
          await browserState(cdp, 'videoFramesDecoded') ?? 0;
      expect((browserDecoded as num).toInt(), greaterThan(0),
          reason: 'browser should have decoded Flutter frames');
    } finally {
      flutterApp.kill();
      await cdp.quit();
      server.kill();
      await flutterApp.exitCode
          .timeout(const Duration(seconds: 3), onTimeout: () => -1);
      await server.exitCode
          .timeout(const Duration(seconds: 3), onTimeout: () => -1);
      await flutterRecv.close();
      await flutterSent.close();
    }
  });
}
