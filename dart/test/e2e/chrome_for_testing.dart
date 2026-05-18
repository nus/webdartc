/// Chrome / Chromium automatic download helper.
///
/// Downloads Chrome + ChromeDriver from the official Chrome for Testing API
/// when the platform is available (mac-arm64, mac-x64, linux64, win64).
///
/// For linux-arm64 (where Chrome for Testing is not available), downloads
/// Chromium from the Playwright CDN instead.
///
/// API endpoints:
///   Chrome for Testing: https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json
///   Playwright CDN:     https://playwright.azureedge.net/builds/chromium/<revision>/chromium-linux-arm64.zip
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

class ChromeForTesting {
  static const String _cftApiUrl =
      'https://googlechromelabs.github.io/chrome-for-testing/'
      'last-known-good-versions-with-downloads.json';

  /// Playwright browsers.json — source of truth for latest Chromium revision.
  static const String _playwrightBrowsersUrl =
      'https://raw.githubusercontent.com/microsoft/playwright/main/'
      'packages/playwright-core/browsers.json';

  static const String _cacheDir = '.local/chrome_for_testing';

  // Paths resolved after [ensureAvailable] is called.
  late final String chromeBinaryPath;
  late final String version;

  /// True when using Playwright Chromium (linux-arm64) instead of Chrome for Testing.
  late final bool isPlaywrightChromium;

  /// Detects the Chrome for Testing platform string, or null for unsupported
  /// platforms (linux-arm64) that need the Playwright fallback.
  static String? get _cftPlatform {
    if (Platform.isMacOS) {
      return _isArm64() ? 'mac-arm64' : 'mac-x64';
    } else if (Platform.isLinux) {
      return _isArm64() ? null : 'linux64'; // no linux-arm64 in CfT
    } else if (Platform.isWindows) {
      return 'win64';
    }
    throw UnsupportedError('Unsupported OS: ${Platform.operatingSystem}');
  }

  static bool _isArm64() {
    final result = Process.runSync('uname', ['-m']);
    final arch = (result.stdout as String).trim();
    return arch == 'aarch64' || arch == 'arm64';
  }

  /// Ensures Chrome/Chromium is downloaded and returns a ready instance.
  static Future<ChromeForTesting> ensureAvailable() async {
    final cft = ChromeForTesting._();
    await cft._init();
    return cft;
  }

  ChromeForTesting._();

  Future<void> _init() async {
    final platform = _cftPlatform;

    if (platform != null) {
      await _initChromeForTesting(platform);
    } else {
      await _initPlaywrightChromium();
    }

    stdout.writeln('[chrome_for_testing] Chrome: $chromeBinaryPath');
  }

  /// Standard Chrome for Testing path (has both chrome + chromedriver).
  Future<void> _initChromeForTesting(String platform) async {
    isPlaywrightChromium = false;

    final json = await _fetchJson(_cftApiUrl);
    final channels = json['channels'] as Map<String, dynamic>;
    final stable = channels['Stable'] as Map<String, dynamic>;
    version = stable['version'] as String;

    final downloads = stable['downloads'] as Map<String, dynamic>;
    final chromeUrl =
        _findPlatformUrl(downloads['chrome'] as List<dynamic>, platform);

    final versionDir = Directory('$_cacheDir/$version');
    if (!versionDir.existsSync()) {
      versionDir.createSync(recursive: true);
    }

    final chromeCached = versionDir
        .listSync()
        .any((e) => e is Directory && e.path.contains('chrome-'));
    if (!chromeCached) {
      stdout.writeln('[chrome_for_testing] Downloading Chrome $version ...');
      await _downloadAndExtractZip(chromeUrl, versionDir.path);
    }

    chromeBinaryPath = _resolveChromeBinary(versionDir.path, platform);
  }

  /// Playwright Chromium fallback for linux-arm64.
  ///
  /// Fetches the latest Chromium revision from Playwright's browsers.json,
  /// then downloads from the Playwright CDN.
  Future<void> _initPlaywrightChromium() async {
    isPlaywrightChromium = true;

    // Fetch the latest revision from Playwright's browsers.json.
    final json = await _fetchJson(_playwrightBrowsersUrl);
    final browsers = json['browsers'] as List<dynamic>;
    final chromium = browsers.firstWhere(
      (b) => (b as Map<String, dynamic>)['name'] == 'chromium',
      orElse: () =>
          throw StateError('No chromium entry in Playwright browsers.json'),
    ) as Map<String, dynamic>;
    final revision = chromium['revision'] as String;
    version = 'playwright-$revision';

    final versionDir = Directory('$_cacheDir/$version');
    if (!versionDir.existsSync()) {
      versionDir.createSync(recursive: true);
    }

    final chromeCached = versionDir
        .listSync()
        .any((e) => e is Directory && e.path.contains('chrome-linux'));
    if (!chromeCached) {
      final url = 'https://playwright.azureedge.net/builds/chromium/'
          '$revision/chromium-linux-arm64.zip';
      stdout.writeln(
          '[chrome_for_testing] Downloading Chromium (Playwright r$revision) ...');
      await _downloadAndExtractZip(url, versionDir.path);
    }

    // Playwright zip extracts to chrome-linux/chrome
    chromeBinaryPath = '${versionDir.path}/chrome-linux/chrome';
    if (!File(chromeBinaryPath).existsSync()) {
      throw StateError(
          'Chromium binary not found at $chromeBinaryPath after extraction');
    }
    await Process.run('chmod', ['+x', chromeBinaryPath]);
  }

  String _findPlatformUrl(List<dynamic> entries, String platform) {
    for (final entry in entries) {
      final map = entry as Map<String, dynamic>;
      if (map['platform'] == platform) {
        return map['url'] as String;
      }
    }
    throw StateError('No download URL found for platform $platform');
  }

  String _resolveChromeBinary(String versionDir, String platform) {
    // Return absolute paths — Windows `Process.start` doesn't reliably
    // resolve forward-slash relative paths the way Unix shells do (the
    // download cache is `.local/...`).
    String resolved(String p) => File(p).absolute.path;

    // macOS: .app bundle
    if (platform.startsWith('mac')) {
      final candidates = [
        '$versionDir/chrome-$platform/Google Chrome for Testing.app/'
            'Contents/MacOS/Google Chrome for Testing',
      ];
      for (final c in candidates) {
        if (File(c).existsSync()) return resolved(c);
      }
    }
    // Linux/Windows: flat binary
    if (platform.startsWith('linux')) {
      final c = '$versionDir/chrome-$platform/chrome';
      if (File(c).existsSync()) return resolved(c);
    }
    if (platform.startsWith('win')) {
      final c = '$versionDir/chrome-$platform/chrome.exe';
      if (File(c).existsSync()) return resolved(c);
    }
    // Fallback: search recursively
    return _findExecutable(versionDir, platform.startsWith('win') ? 'chrome.exe' : 'chrome');
  }

  String _findExecutable(String dir, String name) {
    final result = Process.runSync('find', [dir, '-name', name, '-type', 'f']);
    final lines = (result.stdout as String).trim().split('\n');
    for (final line in lines) {
      if (line.isNotEmpty) return line;
    }
    throw StateError('Cannot find executable "$name" under $dir');
  }

  static Future<Map<String, dynamic>> _fetchJson(String url) async {
    final uri = Uri.parse(url);
    final client = HttpClient();
    try {
      final request = await client.getUrl(uri);
      final response = await request.close();
      final body = await response.transform(utf8.decoder).join();
      return jsonDecode(body) as Map<String, dynamic>;
    } finally {
      client.close();
    }
  }

  static Future<void> _downloadAndExtractZip(
      String url, String destDir) async {
    final uri = Uri.parse(url);
    final tmpFile = File('$destDir/_download.zip');
    final client = HttpClient();
    try {
      final request = await client.getUrl(uri);
      final response = await request.close();
      final sink = tmpFile.openWrite();
      await response.pipe(sink);
      await sink.close();
    } finally {
      client.close();
    }

    final result =
        await Process.run('unzip', ['-q', '-o', tmpFile.path, '-d', destDir]);
    if (result.exitCode != 0) {
      throw ProcessException(
          'unzip', [tmpFile.path, '-d', destDir], result.stderr as String);
    }
    tmpFile.deleteSync();
  }

  /// Launch Chrome directly with --remote-debugging-port and return the CDP
  /// debugging port. No chromedriver required.
  ///
  /// stdout/stderr are subscribed here (so a launch failure can include
  /// captured output in its error). [onStderrLine], if given, also
  /// receives each decoded stderr line — useful for the caller to log
  /// Chrome-side messages without re-listening to `proc.stderr` (which
  /// would throw "Stream has already been listened to").
  Future<(Process, int)> launchChrome({
    List<String> extraArgs = const [],
    void Function(String line)? onStderrLine,
  }) async {
    final userDataDir = await Directory.systemTemp.createTemp('chrome_e2e_');

    if (!Platform.isWindows) {
      await Process.run('chmod', ['+x', chromeBinaryPath]);
    }

    final proc = await Process.start(
      chromeBinaryPath,
      [
        '--remote-debugging-port=0',
        '--user-data-dir=${userDataDir.path}',
        // Prevent macOS Keychain access prompts
        '--password-store=basic',
        '--use-mock-keychain',
        '--disable-features=PasswordManagerOnboarding',
        ...extraArgs,
      ],
      mode: ProcessStartMode.normal,
    );

    // Drain stdout/stderr here so the streams are flowing while we wait
    // for DevToolsActivePort. The caller can't re-listen to these
    // (single-subscription), so we forward stderr lines via the
    // optional callback and buffer the tail for the failure message.
    final stderrTail = _RingTail(capacity: 4096);
    final stdoutTail = _RingTail(capacity: 1024);
    proc.stdout.transform(utf8.decoder).listen(stdoutTail.write);
    proc.stderr.transform(utf8.decoder).listen((chunk) {
      stderrTail.write(chunk);
      if (onStderrLine != null) {
        for (final line in chunk.split('\n')) {
          if (line.isNotEmpty) onStderrLine(line);
        }
      }
    });

    // Read the debugging port from the DevToolsActivePort file.
    final portFile = File('${userDataDir.path}/DevToolsActivePort');
    int? earlyExit;
    unawaited(proc.exitCode.then((code) => earlyExit = code));
    for (var i = 0; i < 100; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
      if (portFile.existsSync()) {
        // On Windows, `existsSync` flips to true the moment Chrome
        // creates the file, but the write often hasn't finished yet
        // and the file is still held exclusively — `readAsStringSync`
        // then throws PathAccessException (errno 32, sharing
        // violation). Swallow and retry on the next tick.
        try {
          final content = portFile.readAsStringSync().trim();
          final lines = content.split('\n');
          if (lines.isNotEmpty) {
            final port = int.tryParse(lines[0]);
            if (port != null) return (proc, port);
          }
        } on FileSystemException {
          // Chrome is mid-write; retry next iteration.
        }
      }
      if (earlyExit != null) break;
    }

    proc.kill();
    final exitCode = earlyExit ??
        await proc.exitCode
            .timeout(const Duration(seconds: 2), onTimeout: () => -1);
    throw StateError(
      'Chrome did not write DevToolsActivePort within 10 seconds.\n'
      '  chrome:        $chromeBinaryPath\n'
      '  exit:          $exitCode\n'
      '  user-data-dir: ${userDataDir.path}\n'
      '  stderr (tail): ${stderrTail.snapshot().trim()}\n'
      '  stdout (tail): ${stdoutTail.snapshot().trim()}',
    );
  }
}

/// Rolling tail buffer — keeps at most [capacity] chars of recent
/// stream output. Used to surface Chrome's last stderr/stdout in
/// launchChrome's failure message without holding unbounded memory.
class _RingTail {
  _RingTail({required this.capacity});

  final int capacity;
  final StringBuffer _buf = StringBuffer();

  void write(String chunk) {
    _buf.write(chunk);
    if (_buf.length > capacity * 2) {
      final s = _buf.toString();
      _buf
        ..clear()
        ..write(s.substring(s.length - capacity));
    }
  }

  String snapshot() {
    final s = _buf.toString();
    return s.length <= capacity ? s : s.substring(s.length - capacity);
  }
}
