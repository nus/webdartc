/// Firefox + GeckoDriver automatic download helper.
///
/// Downloads Firefox and GeckoDriver from official sources when not found
/// on the system. Supports linux64, linux-aarch64, mac-x64, mac-arm64, win64.
///
/// API endpoints:
///   Firefox versions: https://product-details.mozilla.org/1.0/firefox_versions.json
///   Firefox archive:  https://download-installer.cdn.mozilla.net/pub/firefox/releases/
///   GeckoDriver:      https://api.github.com/repos/mozilla/geckodriver/releases/latest
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

class FirefoxForTesting {
  static const String _firefoxVersionsUrl =
      'https://product-details.mozilla.org/1.0/firefox_versions.json';

  static const String _firefoxCdnBase =
      'https://download-installer.cdn.mozilla.net/pub/firefox/releases';

  static const String _geckodriverReleasesUrl =
      'https://api.github.com/repos/mozilla/geckodriver/releases/latest';

  static const String _cacheDir = '.local/firefox_for_testing';

  late final String firefoxBinaryPath;
  late final String geckodriverPath;
  late final String version;
  late final Process _geckodriverProcess;
  late final int geckodriverPort;
  final List<StreamSubscription<ProcessSignal>> _signalSubs = [];
  bool _disposed = false;

  FirefoxForTesting._();

  /// Ensures Firefox and GeckoDriver are available, launches GeckoDriver,
  /// and returns a ready instance.
  static Future<FirefoxForTesting> ensureAvailable() async {
    final ff = FirefoxForTesting._();
    await ff._init();
    return ff;
  }

  Future<void> _init() async {
    // Always download our own Firefox + GeckoDriver for reproducible testing.
    firefoxBinaryPath = await _ensureFirefox();
    stdout.writeln('[firefox_for_testing] Firefox: $firefoxBinaryPath');

    geckodriverPath = await _ensureGeckoDriver();
    stdout.writeln('[firefox_for_testing] GeckoDriver: $geckodriverPath');

    // Launch GeckoDriver on a free port.
    await _launchGeckoDriver();
  }

  /// Kill the GeckoDriver process.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    for (final s in _signalSubs) {
      s.cancel();
    }
    _signalSubs.clear();
    _geckodriverProcess.kill();
  }

  // ── Firefox download ─────────────────────────────────────────────────────────

  /// Download Firefox from Mozilla CDN and return the binary path.
  Future<String> _ensureFirefox() async {
    final json = await _fetchJson(_firefoxVersionsUrl);
    version = json['LATEST_FIREFOX_VERSION'] as String;

    final platform = _firefoxPlatform;
    final archiveFile = _firefoxArchiveName(version, platform);
    final archiveUrl = '$_firefoxCdnBase/$version/$platform/en-US/$archiveFile';

    final versionDir = Directory('$_cacheDir/firefox-$version');
    if (!versionDir.existsSync()) {
      versionDir.createSync(recursive: true);
    }

    final binaryPath = _firefoxBinaryInCache(versionDir.path, platform);
    if (File(binaryPath).existsSync()) return binaryPath;

    stdout.writeln(
        '[firefox_for_testing] Downloading Firefox $version for $platform ...');
    await _downloadAndExtract(archiveUrl, versionDir.path);

    if (!File(binaryPath).existsSync()) {
      throw StateError(
          'Firefox binary not found at $binaryPath after extraction');
    }
    await Process.run('chmod', ['+x', binaryPath]);
    return binaryPath;
  }

  /// Firefox platform directory name for CDN.
  static String get _firefoxPlatform {
    if (Platform.isMacOS) return 'mac';
    if (Platform.isLinux) return _isArm64() ? 'linux-aarch64' : 'linux-x86_64';
    if (Platform.isWindows) return 'win64';
    throw UnsupportedError('Unsupported OS: ${Platform.operatingSystem}');
  }

  /// Firefox archive filename for a given version and platform.
  static String _firefoxArchiveName(String version, String platform) {
    if (platform.startsWith('linux')) return 'firefox-$version.tar.xz';
    if (platform == 'mac') return 'Firefox%20$version.dmg';
    if (platform.startsWith('win')) return 'Firefox%20Setup%20$version.exe';
    throw UnsupportedError('Unknown platform: $platform');
  }

  /// Expected Firefox binary path inside the cache directory.
  static String _firefoxBinaryInCache(String cacheDir, String platform) {
    if (platform.startsWith('linux')) return '$cacheDir/firefox/firefox';
    if (platform == 'mac') {
      return '$cacheDir/Firefox.app/Contents/MacOS/firefox';
    }
    if (platform.startsWith('win')) return '$cacheDir/firefox/firefox.exe';
    throw UnsupportedError('Unknown platform: $platform');
  }

  // ── GeckoDriver download ────────────────────────────────────────────────────

  /// Download GeckoDriver from GitHub Releases and return the binary path.
  Future<String> _ensureGeckoDriver() async {
    final json = await _fetchJson(_geckodriverReleasesUrl);
    final tagName = json['tag_name'] as String; // e.g. "v0.36.0"
    final assets = json['assets'] as List<dynamic>;

    final assetSuffix = _geckodriverAssetSuffix;
    final asset = assets.firstWhere(
      (a) => (a as Map<String, dynamic>)['name']
          .toString()
          .endsWith(assetSuffix),
      orElse: () => throw StateError(
          'No GeckoDriver asset found for suffix "$assetSuffix"'),
    ) as Map<String, dynamic>;

    final downloadUrl = asset['browser_download_url'] as String;
    final versionDir = Directory('$_cacheDir/geckodriver-$tagName');
    if (!versionDir.existsSync()) {
      versionDir.createSync(recursive: true);
    }

    final binaryName =
        Platform.isWindows ? 'geckodriver.exe' : 'geckodriver';
    final binaryPath = '${versionDir.path}/$binaryName';
    if (File(binaryPath).existsSync()) return binaryPath;

    stdout.writeln(
        '[firefox_for_testing] Downloading GeckoDriver $tagName ...');
    await _downloadAndExtract(downloadUrl, versionDir.path);

    if (!File(binaryPath).existsSync()) {
      throw StateError(
          'GeckoDriver binary not found at $binaryPath after extraction');
    }
    await Process.run('chmod', ['+x', binaryPath]);
    return binaryPath;
  }

  /// GeckoDriver asset filename suffix for the current platform.
  static String get _geckodriverAssetSuffix {
    if (Platform.isMacOS) {
      return _isArm64() ? 'macos-aarch64.tar.gz' : 'macos.tar.gz';
    }
    if (Platform.isLinux) {
      return _isArm64() ? 'linux-aarch64.tar.gz' : 'linux64.tar.gz';
    }
    if (Platform.isWindows) return 'win64.zip';
    throw UnsupportedError('Unsupported OS: ${Platform.operatingSystem}');
  }

  // ── GeckoDriver launch ─────────────────────────────────────────────────────

  Future<void> _launchGeckoDriver() async {
    // Find a free port.
    final tempServer = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    geckodriverPort = tempServer.port;
    await tempServer.close();

    _geckodriverProcess = await Process.start(
      geckodriverPath,
      ['--port=$geckodriverPort', '--log=warn'],
    );

    // Ensure geckodriver (and its Firefox child) are killed if the test
    // process is interrupted (Ctrl-C, SIGTERM from test runner timeout,
    // etc.). Without this, geckodriver orphans leak their Firefox child.
    void handleSignal(ProcessSignal sig) {
      dispose();
      exit(sig == ProcessSignal.sigint ? 130 : 143);
    }
    _signalSubs.add(ProcessSignal.sigint.watch().listen(handleSignal));
    if (!Platform.isWindows) {
      _signalSubs.add(ProcessSignal.sigterm.watch().listen(handleSignal));
    }

    // Drain output to prevent pipe deadlock.
    _geckodriverProcess.stdout.listen((_) {});
    _geckodriverProcess.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      if (line.contains('ERROR') || line.contains('FATAL')) {
        // ignore: avoid_print
        print('[geckodriver-err] $line');
      }
    });

    // Wait for GeckoDriver to be ready.
    final client = HttpClient();
    try {
      for (var i = 0; i < 50; i++) {
        try {
          final req = await client
              .getUrl(Uri.parse('http://127.0.0.1:$geckodriverPort/status'));
          final resp = await req.close();
          final body = await resp.transform(utf8.decoder).join();
          final status = jsonDecode(body) as Map<String, dynamic>;
          final value = status['value'] as Map<String, dynamic>;
          if (value['ready'] == true) return;
        } catch (_) {
          // Not ready yet.
        }
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      throw StateError('GeckoDriver did not start within 5 seconds');
    } finally {
      client.close();
    }
  }

  // ── Utilities ───────────────────────────────────────────────────────────────

  static bool _isArm64() {
    final result = Process.runSync('uname', ['-m']);
    final arch = (result.stdout as String).trim();
    return arch == 'aarch64' || arch == 'arm64';
  }

  static Future<Map<String, dynamic>> _fetchJson(String url) async {
    final uri = Uri.parse(url);
    final client = HttpClient();
    try {
      final request = await client.getUrl(uri);
      // GitHub API requires User-Agent header.
      request.headers.set('User-Agent', 'webdartc-e2e-tests');
      final response = await request.close();
      final body = await response.transform(utf8.decoder).join();
      return jsonDecode(body) as Map<String, dynamic>;
    } finally {
      client.close();
    }
  }

  /// Download an archive and extract it into [destDir].
  ///
  /// Supports .tar.xz, .tar.gz, .tar.bz2, .zip, and .dmg (macOS).
  static Future<void> _downloadAndExtract(String url, String destDir) async {
    final uri = Uri.parse(url);
    final tmpFile = File('$destDir/_download${_archiveExtension(url)}');
    final client = HttpClient();
    try {
      // Follow redirects (Mozilla CDN uses 302).
      final request = await client.getUrl(uri);
      request.headers.set('User-Agent', 'webdartc-e2e-tests');
      request.followRedirects = true;
      request.maxRedirects = 5;
      final response = await request.close();
      final sink = tmpFile.openWrite();
      await response.pipe(sink);
    } finally {
      client.close();
    }

    final filename = tmpFile.path;
    ProcessResult result;

    if (filename.endsWith('.tar.xz')) {
      result = await Process.run(
          'tar', ['xf', tmpFile.path, '-C', destDir]);
    } else if (filename.endsWith('.tar.gz') || filename.endsWith('.tgz')) {
      result = await Process.run(
          'tar', ['xzf', tmpFile.path, '-C', destDir]);
    } else if (filename.endsWith('.tar.bz2')) {
      result = await Process.run(
          'tar', ['xjf', tmpFile.path, '-C', destDir]);
    } else if (filename.endsWith('.zip')) {
      result = await Process.run(
          'unzip', ['-q', '-o', tmpFile.path, '-d', destDir]);
    } else if (filename.endsWith('.dmg')) {
      // macOS: mount DMG, copy app, unmount.
      result = await _extractDmg(tmpFile.path, destDir);
    } else {
      throw StateError('Unknown archive format: $url');
    }

    if (result.exitCode != 0) {
      throw ProcessException(
          'extract', [tmpFile.path], '${result.stderr}', result.exitCode);
    }
    tmpFile.deleteSync();
  }

  static String _archiveExtension(String url) {
    // Strip query params for extension detection.
    final path = Uri.parse(url).path;
    if (path.endsWith('.tar.xz')) return '.tar.xz';
    if (path.endsWith('.tar.gz')) return '.tar.gz';
    if (path.endsWith('.tar.bz2')) return '.tar.bz2';
    if (path.endsWith('.tgz')) return '.tgz';
    if (path.endsWith('.zip')) return '.zip';
    if (path.endsWith('.dmg')) return '.dmg';
    if (path.endsWith('.exe')) return '.exe';
    return '.archive';
  }

  /// Extract a .dmg file on macOS by mounting, copying, and unmounting.
  static Future<ProcessResult> _extractDmg(
      String dmgPath, String destDir) async {
    // Mount.
    final mountResult = await Process.run(
        'hdiutil', ['attach', dmgPath, '-nobrowse', '-quiet']);
    if (mountResult.exitCode != 0) return mountResult;

    // Find mounted volume.
    final mountOutput = mountResult.stdout as String;
    final mountPoint = mountOutput
        .split('\n')
        .map((l) => l.trim())
        .where((l) => l.startsWith('/Volumes/'))
        .firstOrNull;
    if (mountPoint == null) {
      return ProcessResult(0, 1, '', 'Could not find mount point in: $mountOutput');
    }

    // Copy Firefox.app.
    final copyResult = await Process.run(
        'cp', ['-R', '$mountPoint/Firefox.app', destDir]);

    // Unmount.
    await Process.run('hdiutil', ['detach', mountPoint, '-quiet']);

    return copyResult;
  }
}
