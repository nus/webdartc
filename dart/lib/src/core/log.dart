/// Minimal injectable debug logger.
///
/// One of the few intentional `dart:io` users outside `lib/transport/`: the
/// logger *implementation* owns the `WEBDARTC_DEBUG` env flag and the stderr
/// sink, so protocol state machines can guard and emit debug output without
/// importing `dart:io` themselves.
library;

import 'dart:io' show Platform, stderr;

/// Whether `WEBDARTC_DEBUG=1` debug logging is enabled. Read once per
/// isolate; the defensive try/catch covers embedders where
/// `Platform.environment` is unavailable.
final bool webdartcDebug = (() {
  try {
    return Platform.environment['WEBDARTC_DEBUG'] == '1';
  } catch (_) {
    return false;
  }
})();

/// Debug log sink, invoked as `webdartcLog(message)`. Defaults to stderr;
/// tests or embedders can reassign it to inject their own sink. Callers on
/// hot paths guard with [webdartcDebug] themselves so message interpolation
/// stays lazy.
void Function(String message) webdartcLog = stderr.writeln;
