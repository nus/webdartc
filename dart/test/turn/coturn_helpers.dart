/// Test helper that spawns a local coturn instance against an ephemeral
/// port. Tests using this file are tagged `coturn`; CI gates them on
/// the `turnserver` binary being available in PATH.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/webdartc.dart';

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
/// [timeout]. Default 15 s — CI runners with cold caches need more
/// headroom than a local dev box.
Future<CoturnInstance> startCoturn({
  Duration timeout = const Duration(seconds: 15),
}) async {
  if (!_hasTurnserver()) {
    throw StateError(
        'turnserver binary not found in PATH — install coturn '
        '(`brew install coturn` on macOS, `apt-get install coturn` on '
        'Linux) to run this test.');
  }

  final port = await _freeUdpPort();
  final process = await Process.start('turnserver', [
    '--no-tls',
    '--no-dtls',
    // --no-cli is deprecated in coturn 4.6+; cli-port=0 disables the
    // admin TCP listener the same way.
    '--cli-port=0',
    // coturn 4.6 still validates `--allow-loopback-peers` against the
    // CLI password even when the CLI is disabled; set a dummy so the
    // server doesn't refuse to start with "allow_loopback_peers and
    // empty cli password cannot be used together".
    '--cli-password=unused',
    '--listening-port=$port',
    '--listening-ip=127.0.0.1',
    '--realm=$coturnRealm',
    '--user=$coturnUser:$coturnPass',
    '--lt-cred-mech',
    '--simple-log',
    '--min-port=49160',
    '--max-port=49200',
    // coturn 4.5+ rejects CreatePermission for loopback peer addresses
    // by default; in this test both PCs sit on 127.0.0.1 so without
    // this flag the relay-only traffic test gets 403 Forbidden.
    '--allow-loopback-peers',
  ]);
  // Capture coturn's output so a startup failure (bad CLI flag, missing
  // /etc/turnserver.conf overrides, etc.) lands in the error message
  // instead of vanishing into a silent timeout.
  final logBuffer = StringBuffer();
  void capture(List<int> bytes) {
    logBuffer.write(utf8.decode(bytes, allowMalformed: true));
  }
  process.stdout.listen(capture);
  process.stderr.listen(capture);

  try {
    await _waitUntilStunRespondsOn(port, timeout);
  } catch (e) {
    process.kill(ProcessSignal.sigkill);
    // Await exit so the stdout/stderr listeners flush every last byte
    // into logBuffer before we render the error message.
    await process.exitCode;
    throw StateError(
        'coturn did not come up on port $port: $e\n'
        '--- coturn output ---\n$logBuffer\n'
        '--- end coturn output ---');
  }
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

/// Wire trickled candidates from [from] to [to]. Returns the
/// subscription so tests can cancel it from a `finally` block if needed.
StreamSubscription<PeerConnectionIceEvent> forwardIceCandidates(
    PeerConnection from, PeerConnection to) {
  return from.onIceCandidate.listen((evt) {
    to.addIceCandidate(IceCandidateInit(
      candidate: evt.candidate,
      sdpMid: evt.sdpMid,
      sdpMLineIndex: evt.sdpMLineIndex,
    ));
  });
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
      await got.future.timeout(const Duration(milliseconds: 250));
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
