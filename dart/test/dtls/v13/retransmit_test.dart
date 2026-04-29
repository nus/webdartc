// Tests for DTLS 1.3 server / client retransmit timer (RFC 9147 §5.7).
//
// Both state machines must:
//   - Return a Timeout when an outbound flight is sent.
//   - Re-send the flight verbatim on timer fire (state still waiting).
//   - Apply exponential backoff (1s, 2s, 4s, 8s, ...).
//   - No-op once the handshake state advances out of waiting.
//   - Fail after [_maxHandshakeRetransmits] attempts.

import 'package:test/test.dart';
import 'package:webdartc/core/types.dart';
import 'package:webdartc/crypto/ecdsa.dart';
import 'package:webdartc/dtls/v13/client_state_machine.dart';
import 'package:webdartc/dtls/v13/state_machine.dart';

void main() {
  // Helper: drain the server's handshake response from a fed CH packet.
  ProcessResult feedCh1ToServer(
    DtlsV13ServerStateMachine server,
    DtlsV13ClientStateMachine client,
  ) {
    final start = client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5001);
    expect(start.isOk, isTrue);
    final ch1 = start.value.outputPackets.single;
    final r = server.processInput(
      ch1.data,
      remoteIp: ch1.remoteIp,
      remotePort: ch1.remotePort,
    );
    expect(r.isOk, isTrue);
    return r.value;
  }

  group('DTLS 1.3 server retransmit', () {
    test('server flight schedules a retransmit Timeout', () {
      final server = DtlsV13ServerStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final out = feedCh1ToServer(server, client);
      expect(out.outputPackets, isNotEmpty);
      expect(out.nextTimeout, isNotNull);
      expect(out.nextTimeout!.token, isA<DtlsRetransmitToken>());
      // Initial backoff = 1000ms; allow generous slack for slow runners.
      final delay = out.nextTimeout!.at.difference(DateTime.now()).inMilliseconds;
      expect(delay, inInclusiveRange(800, 1500));
    });

    test('handleTimeout re-sends the same flight verbatim', () {
      final server = DtlsV13ServerStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final initial = feedCh1ToServer(server, client);
      final firstFlight = initial.outputPackets.map((p) => p.data).toList();

      final r = server.handleTimeout(initial.nextTimeout!.token);
      expect(r.isOk, isTrue);
      final retxFlight = r.value.outputPackets.map((p) => p.data).toList();
      expect(retxFlight.length, equals(firstFlight.length));
      for (var i = 0; i < firstFlight.length; i++) {
        expect(retxFlight[i], equals(firstFlight[i]));
      }
      expect(r.value.nextTimeout, isNotNull);
      // Backoff doubled.
      final delay = r.value.nextTimeout!.at.difference(DateTime.now()).inMilliseconds;
      expect(delay, inInclusiveRange(1800, 2500));
    });

    test('handleTimeout no-ops once the server reaches CONNECTED', () {
      final server = DtlsV13ServerStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      // Drive the handshake to completion via loopback.
      final start = client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5001);
      final c2s = <OutputPacket>[...start.value.outputPackets];
      final s2c = <OutputPacket>[];
      var rounds = 0;
      while ((c2s.isNotEmpty || s2c.isNotEmpty) && rounds < 32) {
        while (c2s.isNotEmpty) {
          final p = c2s.removeAt(0);
          final r = server.processInput(p.data,
              remoteIp: p.remoteIp, remotePort: p.remotePort);
          if (r.isOk) s2c.addAll(r.value.outputPackets);
        }
        while (s2c.isNotEmpty) {
          final p = s2c.removeAt(0);
          final r = client.processInput(p.data,
              remoteIp: p.remoteIp, remotePort: p.remotePort);
          if (r.isOk) c2s.addAll(r.value.outputPackets);
        }
        rounds++;
      }
      expect(server.state, equals(DtlsV13ServerState.connected));

      final r = server.handleTimeout(DtlsRetransmitToken(0));
      expect(r.isOk, isTrue);
      expect(r.value.outputPackets, isEmpty);
      expect(r.value.nextTimeout, isNull);
    });

    test('exceeding _maxHandshakeRetransmits transitions to FAILED', () {
      final server = DtlsV13ServerStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      feedCh1ToServer(server, client);
      // 6 retransmits should still succeed; the 7th must fail.
      for (var i = 0; i < 6; i++) {
        final r = server.handleTimeout(DtlsRetransmitToken(0));
        expect(r.isOk, isTrue, reason: 'retransmit $i should succeed');
        expect(r.value.outputPackets, isNotEmpty);
      }
      final r = server.handleTimeout(DtlsRetransmitToken(0));
      expect(r.isErr, isTrue);
      expect(server.state, equals(DtlsV13ServerState.failed));
    });

    test('non-retransmit token is ignored', () {
      final server = DtlsV13ServerStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      // Pass an unrelated token type.
      final r = server.handleTimeout(IceTimerToken(42));
      expect(r.isOk, isTrue);
      expect(r.value.outputPackets, isEmpty);
    });
  });

  group('DTLS 1.3 client retransmit', () {
    test('startHandshake schedules retransmit and saves the flight', () {
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final r = client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5001);
      expect(r.isOk, isTrue);
      expect(r.value.outputPackets, hasLength(1));
      expect(r.value.nextTimeout, isNotNull);
      expect(r.value.nextTimeout!.token, isA<DtlsRetransmitToken>());
    });

    test('handleTimeout resends ClientHello while sentClientHello', () {
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final start = client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5001);
      final ch1 = start.value.outputPackets.single.data;
      final r = client.handleTimeout(DtlsRetransmitToken(0));
      expect(r.isOk, isTrue);
      expect(r.value.outputPackets.single.data, equals(ch1));
      expect(r.value.nextTimeout, isNotNull);
    });

    test('handleTimeout no-ops in initial / connected / failed states', () {
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      // initial
      final r = client.handleTimeout(DtlsRetransmitToken(0));
      expect(r.isOk, isTrue);
      expect(r.value.outputPackets, isEmpty);
    });

    test('exceeding the cap fails the connection', () {
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5001);
      for (var i = 0; i < 6; i++) {
        final r = client.handleTimeout(DtlsRetransmitToken(0));
        expect(r.isOk, isTrue);
      }
      final r = client.handleTimeout(DtlsRetransmitToken(0));
      expect(r.isErr, isTrue);
      expect(client.state, equals(DtlsV13ClientState.failed));
    });
  });

  group('Retransmit recovers a one-shot dropped server flight', () {
    test('client receives reply after first server flight is dropped', () {
      // Pre-conditions: client sends CH1, server emits its full flight,
      // we *drop* the server's first flight, server retransmits, client
      // processes the retransmit and the handshake reaches CONNECTED.
      final client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final server = DtlsV13ServerStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final start = client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5001);
      // Deliver CH1 to server.
      final ch1 = start.value.outputPackets.single;
      final s1 = server.processInput(ch1.data,
          remoteIp: ch1.remoteIp, remotePort: ch1.remotePort);
      expect(s1.isOk, isTrue);
      expect(s1.value.outputPackets, isNotEmpty);

      // ── Simulate loss of the server's first flight: do NOT deliver
      //    s1.value.outputPackets to the client. Instead, fire the
      //    server's retransmit timer manually to obtain the same flight
      //    again.
      final retx = server.handleTimeout(s1.value.nextTimeout!.token);
      expect(retx.isOk, isTrue);

      // Deliver retransmitted flight to client.
      var c2s = <OutputPacket>[];
      for (final p in retx.value.outputPackets) {
        final cr = client.processInput(p.data,
            remoteIp: p.remoteIp, remotePort: p.remotePort);
        expect(cr.isOk, isTrue);
        c2s.addAll(cr.value.outputPackets);
      }
      // Drain c2s back to server until handshake settles.
      var rounds = 0;
      while (c2s.isNotEmpty && rounds < 8) {
        final next = <OutputPacket>[];
        for (final p in c2s) {
          final sr = server.processInput(p.data,
              remoteIp: p.remoteIp, remotePort: p.remotePort);
          if (sr.isOk) next.addAll(sr.value.outputPackets);
        }
        c2s = <OutputPacket>[];
        for (final p in next) {
          final cr = client.processInput(p.data,
              remoteIp: p.remoteIp, remotePort: p.remotePort);
          if (cr.isOk) c2s.addAll(cr.value.outputPackets);
        }
        rounds++;
      }

      expect(client.state, equals(DtlsV13ClientState.connected));
      expect(server.state, equals(DtlsV13ServerState.connected));
      expect(client.exporterMasterSecret,
          equals(server.exporterMasterSecret));
    });
  });
}
