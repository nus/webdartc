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

  /// TLS listening port when [startCoturn] was called with `withTls: true`,
  /// `null` otherwise. coturn exposes plain UDP/TCP on [port] and
  /// TLS-over-TCP on this separate port.
  final int? tlsPort;

  /// Self-signed certificate / key directory the spawned coturn loaded.
  /// `null` when `withTls: false`. Removed recursively on [stop].
  final Directory? certDir;
  String? get certPath => certDir == null ? null : '${certDir!.path}/cert.pem';
  String? get keyPath => certDir == null ? null : '${certDir!.path}/key.pem';

  CoturnInstance._(this.process, this.port, {this.tlsPort, this.certDir});

  Future<void> stop() async {
    process.kill(ProcessSignal.sigterm);
    try {
      await process.exitCode.timeout(const Duration(seconds: 3));
    } on TimeoutException {
      process.kill(ProcessSignal.sigkill);
      await process.exitCode;
    }
    if (certDir != null) {
      try {
        certDir!.deleteSync(recursive: true);
      } catch (_) {}
    }
  }
}

/// Pick a UDP loopback port the OS just confirmed was free. Used for the
/// main `--listening-port`, where the post-bind STUN probe verifies the
/// UDP socket is healthy.
Future<int> _freeUdpPort() async {
  final probe = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  probe.close();
  return port;
}

/// Pick a TCP loopback port. The TLS listener is TCP-only and Linux
/// keeps UDP / TCP port spaces fully independent — a UDP probe says
/// nothing about TCP availability, and the resulting race (TLS bind
/// silently falling back, TURN client connecting to whatever was
/// already on that TCP port) showed up as the `coturn_tls_relay_test`
/// flake (ECONNRESET on Client Hello).
Future<int> _freeTcpPort() async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  return port;
}

/// Spawn coturn on a free port and wait until it answers a STUN Binding
/// request. Throws if the binary is missing or doesn't come up within
/// [timeout]. Default 15 s — CI runners with cold caches need more
/// headroom than a local dev box.
///
/// Pass [withTls] to additionally serve TLS-over-TCP on
/// [CoturnInstance.tlsPort], using a freshly generated self-signed
/// certificate. Requires the `openssl` CLI to be on PATH.
Future<CoturnInstance> startCoturn({
  Duration timeout = const Duration(seconds: 15),
  bool withTls = false,
}) async {
  if (!_hasBinary('turnserver')) {
    throw StateError(
        'turnserver binary not found in PATH — install coturn '
        '(`brew install coturn` on macOS, `apt-get install coturn` on '
        'Linux) to run this test.');
  }

  final port = await _freeUdpPort();
  int? tlsPort;
  Directory? certDir;
  if (withTls) {
    if (!_hasBinary('openssl')) {
      throw StateError(
          'openssl binary not found in PATH — needed to generate the '
          'self-signed coturn cert for TLS tests.');
    }
    tlsPort = await _freeTcpPort();
    certDir = _generateSelfSignedCert();
  }
  final certPath = certDir == null ? null : '${certDir.path}/cert.pem';
  final keyPath = certDir == null ? null : '${certDir.path}/key.pem';

  final process = await Process.start('turnserver', [
    if (!withTls) '--no-tls',
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
    if (withTls) '--tls-listening-port=$tlsPort',
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
    if (withTls) ...['--cert=$certPath', '--pkey=$keyPath'],
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
    if (withTls) {
      // STUN-on-UDP responding doesn't imply the TLS-over-TCP listener
      // has bound — coturn brings them up on separate threads. *And*
      // the TCP listener finishes `accept()` slightly before the TLS
      // subsystem (OpenSSL init + cert load) is ready, so a pure TCP
      // probe still races the handshake (ECONNRESET inside
      // `_RawSecureSocket._tryFilter`). Run a real TLS handshake as
      // the readiness check.
      await _waitUntilTlsReady(tlsPort!, timeout);
    }
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
  return CoturnInstance._(process, port,
      tlsPort: tlsPort, certDir: certDir);
}

bool _hasBinary(String name) {
  try {
    return Process.runSync('which', [name]).exitCode == 0;
  } catch (_) {
    return false;
  }
}

/// Generate a throwaway self-signed cert/key pair so coturn can serve
/// TLS in tests. Returns the temp directory holding `cert.pem` /
/// `key.pem`; the directory is deleted recursively when the
/// [CoturnInstance] is stopped. The subject is `localhost` even though
/// we connect via `127.0.0.1` — production code should rely on
/// platform trust roots, but the test passes
/// `onBadTurnCertificate: (_) => true` so the mismatch doesn't matter.
Directory _generateSelfSignedCert() {
  final dir = Directory.systemTemp.createTempSync('coturn-tls-');
  final r = Process.runSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-days', '1', '-nodes',
    '-keyout', '${dir.path}/key.pem',
    '-out', '${dir.path}/cert.pem',
    '-subj', '/CN=localhost',
  ]);
  if (r.exitCode != 0) {
    dir.deleteSync(recursive: true);
    throw StateError('openssl req failed: ${r.stderr}');
  }
  return dir;
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

/// Stand up two relay-only [PeerConnection]s against [iceServers], run
/// the offer/answer dance with trickle forwarding, and wait for both
/// to reach `connected`. Used by the coturn relay-traffic / TCP / TLS
/// tests so each one only differs in the [iceServers] entry (and
/// optional [settingEngine] for TLS cert callbacks).
///
/// [whileConnected], if supplied, fires once both PCs are connected,
/// before they're torn down — handy for poking at `getStats`,
/// `turnAllocations`, etc. without re-running the handshake.
Future<void> runRelayHandshake({
  required List<IceServer> iceServers,
  required String dataChannelLabel,
  SettingEngine? settingEngine,
  Duration connectedTimeout = const Duration(seconds: 25),
  Future<void> Function(PeerConnection pcA, PeerConnection pcB)?
      whileConnected,
}) async {
  final config = PeerConnectionConfiguration(
    iceServers: iceServers,
    iceTransportPolicy: IceTransportPolicy.relay,
  );
  final pcA = PeerConnection(
      configuration: config,
      settingEngine: settingEngine ?? const SettingEngine());
  final pcB = PeerConnection(
      configuration: config,
      settingEngine: settingEngine ?? const SettingEngine());

  try {
    forwardIceCandidates(pcA, pcB);
    forwardIceCandidates(pcB, pcA);

    pcA.createDataChannel(dataChannelLabel);

    final offer = await pcA.createOffer();
    await pcA.setLocalDescription(offer);
    await pcB.setRemoteDescription(offer);
    final answer = await pcB.createAnswer();
    await pcB.setLocalDescription(answer);
    await pcA.setRemoteDescription(answer);

    await Future.wait([
      pcA.onConnectionStateChange
          .firstWhere((s) => s == PeerConnectionState.connected),
      pcB.onConnectionStateChange
          .firstWhere((s) => s == PeerConnectionState.connected),
    ]).timeout(connectedTimeout);

    // The relay-only policy means the only candidate ICE could have
    // nominated is the TURN-derived relay; both PCs should hold a
    // single allocation against the configured server.
    for (final pc in [pcA, pcB]) {
      if (pc.turnAllocations.length != 1) {
        throw StateError(
            'expected 1 allocation, got ${pc.turnAllocations.length}');
      }
    }

    if (whileConnected != null) {
      await whileConnected(pcA, pcB);
    }
  } finally {
    await pcA.close();
    await pcB.close();
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

/// Complete a TLS handshake against [port] and discard the connection.
/// `onBadCertificate: (_) => true` accepts the self-signed cert coturn
/// is serving — production code must not do this, but the probe only
/// cares whether coturn's TLS layer can complete a handshake.
///
/// A pure TCP probe isn't enough: coturn's TCP listener finishes
/// `accept()` slightly before its TLS subsystem (OpenSSL init + cert
/// load) is ready, and a TCP-only probe races straight past that
/// window. The real-handshake probe forces us to wait until coturn
/// can actually answer a Client Hello.
Future<void> _waitUntilTlsReady(int port, Duration timeout) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    try {
      final s = await SecureSocket.connect(
        InternetAddress.loopbackIPv4, port,
        onBadCertificate: (_) => true,
        timeout: const Duration(milliseconds: 500),
      );
      s.destroy();
      return;
    } catch (_) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }
  throw StateError('no TLS handshake on 127.0.0.1:$port within $timeout');
}
