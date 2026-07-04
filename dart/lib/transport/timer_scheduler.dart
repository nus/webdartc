part of 'transport_controller.dart';

/// Route for one family of [TimerToken]s: which state machine handles the
/// timeout and how the resulting output packets reach the wire.
final class _TimerRoute {
  final Result<ProcessResult, ProtocolError> Function(TimerToken) handle;
  final void Function(List<OutputPacket>) sendOutputs;

  const _TimerRoute({required this.handle, required this.sendOutputs});
}

/// Keyed timer scheduling for all protocol state machines.
///
/// Token dispatch is a registry keyed by the token's runtime type (every
/// [TimerToken] subclass is a final leaf class), replacing the old
/// `token is X || token is Y` chains: the controller registers each state
/// machine's token types and output routing once, and adding a protocol
/// can't silently miss the dispatch switch.
final class TimerScheduler {
  final Map<String, Timer> _timers = {};
  final Map<Type, _TimerRoute> _routes = {};

  /// Register [route] for every token type in [tokenTypes].
  void _registerRoute(List<Type> tokenTypes, _TimerRoute route) {
    for (final t in tokenTypes) {
      _routes[t] = route;
    }
  }

  /// Schedule (or replace) the timer stored under [key].
  void schedule(Timeout? timeout, String key) {
    if (timeout == null) return;
    _timers[key]?.cancel();
    final delay = timeout.at.difference(DateTime.now());
    final effectiveDelay = delay.isNegative ? Duration.zero : delay;
    _timers[key] = Timer(effectiveDelay, () => _fire(timeout.token, key));
  }

  void _fire(TimerToken token, String key) {
    _timers.remove(key);
    final route = _routes[token.runtimeType];
    if (route == null) return;
    final result = route.handle(token);
    if (result.isOk) {
      route.sendOutputs(result.value.outputPackets);
      schedule(result.value.nextTimeout, key);
    }
  }

  void cancelAll() {
    for (final timer in _timers.values) {
      timer.cancel();
    }
    _timers.clear();
  }
}
