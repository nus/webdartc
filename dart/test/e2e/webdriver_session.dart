/// Minimal W3C WebDriver client for Firefox via GeckoDriver.
///
/// Implements only the subset needed by E2E tests:
///   - Create session with Firefox capabilities
///   - Navigate to URL
///   - Execute synchronous script
///   - Delete session
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// A W3C WebDriver session connected to GeckoDriver.
final class WebDriverSession {
  final int _geckodriverPort;
  final String _sessionId;

  WebDriverSession._(this._geckodriverPort, this._sessionId);

  /// Create a new Firefox WebDriver session.
  ///
  /// [geckodriverPort] is the port GeckoDriver is listening on.
  /// [firefoxBinaryPath] is the path to the Firefox binary.
  /// [headless] enables headless mode (default true).
  /// [extraPrefs] are additional Firefox preferences to set.
  static Future<WebDriverSession> create({
    required int geckodriverPort,
    required String firefoxBinaryPath,
    bool headless = true,
    Map<String, dynamic> extraPrefs = const {},
  }) async {
    final prefs = <String, dynamic>{
      // Fake media devices for WebRTC testing.
      'media.navigator.streams.fake': true,
      'media.navigator.permission.disabled': true,
      // Disable mDNS ICE candidate obfuscation — webdartc can't resolve .local
      // hostnames, so we need real IP addresses in candidates.
      'media.peerconnection.ice.obfuscate_host_addresses': false,
      // Disable safe mode dialogs.
      'toolkit.startup.max_resumed_crashes': -1,
      ...extraPrefs,
    };

    final firefoxOptions = <String, dynamic>{
      'binary': firefoxBinaryPath,
      'prefs': prefs,
      if (headless) 'args': ['-headless'],
    };

    final capabilities = {
      'capabilities': {
        'alwaysMatch': {
          'browserName': 'firefox',
          'moz:firefoxOptions': firefoxOptions,
          // Accept all insecure certs (loopback).
          'acceptInsecureCerts': true,
        },
      },
    };

    final body = await _post(geckodriverPort, '/session', capabilities);
    final value = body['value'] as Map<String, dynamic>;
    final sessionId = value['sessionId'] as String;
    return WebDriverSession._(geckodriverPort, sessionId);
  }

  /// Navigate to the given URL.
  Future<void> navigateTo(String url) async {
    await _post(_geckodriverPort, '/session/$_sessionId/url', {'url': url});
    // Brief delay for page load.
    await Future<void>.delayed(const Duration(milliseconds: 500));
  }

  /// Execute a synchronous JavaScript script and return its result.
  ///
  /// Scripts use WebDriver calling convention: `arguments[0]`, `arguments[1]`,
  /// etc. for parameters, and `return` for results.
  Future<dynamic> executeScript(String script,
      [List<dynamic> args = const []]) async {
    final body = await _post(
      _geckodriverPort,
      '/session/$_sessionId/execute/sync',
      {'script': script, 'args': args},
    );
    final value = body['value'];
    return value;
  }

  /// Delete the session and close Firefox.
  Future<void> quit() async {
    try {
      await _delete(_geckodriverPort, '/session/$_sessionId');
    } catch (_) {
      // Session may already be closed.
    }
  }

  // ── HTTP helpers ────────────────────────────────────────────────────────────

  static Future<Map<String, dynamic>> _post(
      int port, String path, Map<String, dynamic> body) async {
    final client = HttpClient();
    try {
      final req =
          await client.postUrl(Uri.parse('http://127.0.0.1:$port$path'));
      req.headers.contentType = ContentType.json;
      req.write(jsonEncode(body));
      final resp = await req.close();
      final respBody = await resp.transform(utf8.decoder).join();
      final json = jsonDecode(respBody) as Map<String, dynamic>;
      _checkError(json, path);
      return json;
    } finally {
      client.close();
    }
  }

  static Future<void> _delete(int port, String path) async {
    final client = HttpClient();
    try {
      final req =
          await client.deleteUrl(Uri.parse('http://127.0.0.1:$port$path'));
      final resp = await req.close();
      await resp.drain<void>();
    } finally {
      client.close();
    }
  }

  static void _checkError(Map<String, dynamic> json, String path) {
    final value = json['value'];
    if (value is Map<String, dynamic> && value.containsKey('error')) {
      throw Exception(
          'WebDriver error on $path: ${value['error']} — ${value['message']}');
    }
  }
}
