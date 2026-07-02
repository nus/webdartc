/// E2E for the video_receiver sample: browser (fake camera) → Dart decoder
/// (VideoToolbox for H.264, libvpx for VP9). Chrome is launched with
/// `--use-fake-device-for-media-stream` so getUserMedia returns a canned
/// green-bar video that the browser sends to the Dart receiver. We poll the
/// receiver's stdout for `[video_receiver] decoded #N` lines to verify a
/// frame decoded. The VP9 case exercises the depacketizer against Chrome's
/// real (non-flexible-mode) VP9 sender.
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
import 'dart_helper_process.dart';

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

  for (final codec in ['h264', 'vp9']) {
    test('Dart receiver decodes $codec frames sent from browser fake camera',
        () async {
      final port = await _findFreePort();

      final receiver = await spawnDartHelper(
        'example/video_receiver/server.dart',
        ['--port=$port', '--codec=$codec'],
      );
      final decodedController = StreamController<int>.broadcast();
      final decodedRe = RegExp(r'\[video_receiver\] decoded #(\d+)');
      receiver.stdout
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen((line) {
        // ignore: avoid_print
        print('[receiver] $line');
        final m = decodedRe.firstMatch(line);
        if (m != null) decodedController.add(int.parse(m.group(1)!));
      });
      receiver.stderr.transform(utf8.decoder).listen((line) {
        // ignore: avoid_print
        stderr.write('[receiver-err] $line');
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
      await cdp.navigateTo('http://127.0.0.1:$port/');

      // Skip when the browser build lacks an encoder for the requested codec
      // (e.g. Playwright's Chromium has no H.264 encoder). We rely on the
      // browser sending that codec's RTP back to Dart.
      final codecsRaw = await cdp.executeScript(
        'const c = RTCRtpSender.getCapabilities("video").codecs; '
        'return c.map(x => x.mimeType).join(",");',
      );
      final codecList = (codecsRaw as String? ?? '').toLowerCase();
      if (!codecList.contains('video/$codec')) {
        markTestSkipped(
            'browser lacks video/$codec encoder (codecs=$codecList)');
        await cdp.quit();
        receiver.kill();
        await receiver.exitCode
            .timeout(const Duration(seconds: 3), onTimeout: () => -1);
        return;
      }

      try {
        final first = await decodedController.stream
            .first
            .timeout(const Duration(seconds: 60));
        expect(first, greaterThan(0));
      } finally {
        await cdp.quit();
        receiver.kill();
        await receiver.exitCode
            .timeout(const Duration(seconds: 3), onTimeout: () => -1);
      }
    });
  }
}
