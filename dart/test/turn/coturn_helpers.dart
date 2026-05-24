/// Test helper that spawns a local coturn instance against an ephemeral
/// port. Tests using this file are tagged `coturn`; CI gates them on
/// the `turnserver` binary being available in PATH.
library;

import 'dart:async';
import 'dart:io';

/// Long-term credential the spawned coturn instance accepts. Stable so
/// tests can build the IceServer config without coordinating with the
/// helper.
const coturnUser = 'test';
const coturnPass = 'test';
const coturnRealm = 'webdartc.test';

class CoturnInstance {
  final Process process;
  final int port;

  CoturnInstance._(this.process, this.port);

  Future<void> stop() async {
    process.kill(ProcessSignal.sigterm);
    try {
      await process.exitCode.timeout(const Duration(seconds: 3));
    } on TimeoutException {
      process.kill(ProcessSignal.sigkill);
      await process.exitCode;
    }
  }
}

/// Pick a port the OS just confirmed was free. There's a tiny race
/// window between close + coturn's bind, but it's vanishingly small for
/// localhost test runs.
Future<int> _freeUdpPort() async {
  final probe = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  probe.close();
  return port;
}

/// Spawn coturn on a free port and wait until it answers a STUN Binding
/// request. Throws if the binary is missing or doesn't come up within
/// [timeout].
Future<CoturnInstance> startCoturn({
  Duration timeout = const Duration(seconds: 5),
}) async {
  if (!_hasTurnserver()) {
    throw StateError(
        'turnserver binary not found in PATH — install coturn '
        '(`brew install coturn` on macOS) to run this test.');
  }

  final port = await _freeUdpPort();
  final process = await Process.start('turnserver', [
    '--no-tls',
    '--no-dtls',
    // --no-cli is deprecated in coturn 4.6+; setting cli-port=0
    // disables the admin TCP listener the same way.
    '--cli-port=0',
    '--listening-port=$port',
    '--listening-ip=127.0.0.1',
    '--realm=$coturnRealm',
    '--user=$coturnUser:$coturnPass',
    '--lt-cred-mech',
    '--simple-log',
    '--no-stdout-log',
    '--min-port=49160',
    '--max-port=49200',
  ]);
  // Forward coturn's diagnostics to the test runner's stderr so a
  // surprise failure shows up in CI logs.
  process.stdout.listen((_) {});
  process.stderr.listen((bytes) => stderr.add(bytes));

  await _waitUntilStunRespondsOn(port, timeout).onError((e, _) async {
    process.kill(ProcessSignal.sigkill);
    throw StateError('coturn did not come up on port $port: $e');
  });
  return CoturnInstance._(process, port);
}

bool _hasTurnserver() {
  try {
    final r = Process.runSync('which', ['turnserver']);
    return r.exitCode == 0;
  } catch (_) {
    return false;
  }
}

/// Send a STUN Binding request and wait for any response — the simplest
/// proof that coturn has finished initialising its UDP listener.
Future<void> _waitUntilStunRespondsOn(int port, Duration timeout) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    final socket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
    final got = Completer<void>();
    final sub = socket.listen((event) {
      if (event != RawSocketEvent.read) return;
      final dg = socket.receive();
      if (dg != null && !got.isCompleted) got.complete();
    });
    // Minimal STUN Binding Request: 20 bytes, type 0x0001, magic cookie.
    final req = [
      0x00, 0x01, 0x00, 0x00,
      0x21, 0x12, 0xA4, 0x42,
      ...List.filled(12, 0xCC),
    ];
    socket.send(req, InternetAddress.loopbackIPv4, port);
    try {
      await got.future.timeout(const Duration(milliseconds: 200));
      await sub.cancel();
      socket.close();
      return;
    } on TimeoutException {
      await sub.cancel();
      socket.close();
    }
  }
  throw StateError('no STUN response from 127.0.0.1:$port within $timeout');
}
