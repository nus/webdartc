/// Common browser driver abstraction for E2E tests.
///
/// Allows the same test scenarios to run against Chrome (via CDP) and
/// Firefox (via W3C WebDriver / GeckoDriver) with a uniform API.
library;

import 'dart:async';

/// A controlled browser session that tests can drive.
abstract interface class BrowserDriver {
  /// Navigate the browser to [url] and wait briefly for the page to load.
  Future<void> navigateTo(String url);

  /// Execute a synchronous JavaScript [script] and return its result.
  ///
  /// Scripts use WebDriver-style `arguments[N]` parameter access and
  /// `return` for values.
  Future<dynamic> executeScript(String script,
      [List<dynamic> args = const []]);

  /// Close the browser session.
  Future<void> quit();
}

/// Scenario keys used by [BrowserBackend.skipReasonFor] for skip logic.
abstract final class ScenarioKey {
  static const String dataChannelLocalOfferer = 'scenario1';
  static const String dataChannelBrowserOfferer = 'scenario1b';
  static const String mediaAudio = 'scenario2';
  static const String mediaVideo = 'scenario2b';
  static const String trickleIce = 'scenario3';
  static const String mediaEcho = 'scenario4';
  static const String videoReflect = 'scenario5';
  static const String videoReflectRtp = 'scenario5b';
  static const String packetLossIce = 'pl_ice';
  static const String packetLossDtls = 'pl_dtls';
  static const String packetLossSctp = 'pl_sctp';
  static const String packetLossSrtp = 'pl_srtp';
  static const String delayJitter = 'delay_jitter';
}

/// A backend that initializes one browser engine (Chrome or Firefox) once
/// per test run and creates fresh sessions for individual tests.
abstract interface class BrowserBackend {
  /// Display name used in test group prefixes (e.g. "Chrome", "Firefox").
  String get name;

  /// Prepare the backend (download browser, launch driver processes, etc.).
  Future<void> initialize();

  /// Release any backend-wide resources.
  Future<void> dispose();

  /// Create a new browser session for a single test.
  Future<BrowserDriver> createSession();

  /// Returns a skip reason if this backend cannot run [scenarioKey], or
  /// null to run it normally.
  String? skipReasonFor(String scenarioKey);
}
