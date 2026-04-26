// DTLS 1.3 KeyUpdate (RFC 8446 §4.6.3 / RFC 9147 §6.1).
//
// Drives a full handshake to CONNECTED, then exercises:
//   * client-initiated KeyUpdate(notRequested) — application data
//     continues to flow under fresh keys for one direction.
//   * server-initiated KeyUpdate(requested) — receiver MUST reciprocate
//     before sending its next application_data record.
//   * Multiple consecutive KeyUpdates — both directions track epochs
//     independently.
//   * Wire-format / parser sanity for the 1-byte body.

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/core/state_machine.dart';
import 'package:webdartc/crypto/ecdsa.dart';
import 'package:webdartc/dtls/v13/client_state_machine.dart';
import 'package:webdartc/dtls/v13/handshake.dart';
import 'package:webdartc/dtls/v13/state_machine.dart';

void _drainHandshake(
  DtlsV13ClientStateMachine client,
  DtlsV13ServerStateMachine server, {
  required List<OutputPacket> initial,
}) {
  final clientToServer = <OutputPacket>[...initial];
  final serverToClient = <OutputPacket>[];
  var rounds = 0;
  while ((clientToServer.isNotEmpty || serverToClient.isNotEmpty) &&
      rounds < 32) {
    while (clientToServer.isNotEmpty) {
      final p = clientToServer.removeAt(0);
      final r = server.processInput(p.data,
          remoteIp: p.remoteIp, remotePort: p.remotePort);
      expect(r.isOk, isTrue,
          reason: r.isErr ? 'server error: ${r.error}' : '');
      serverToClient.addAll(r.value.outputPackets);
    }
    while (serverToClient.isNotEmpty) {
      final p = serverToClient.removeAt(0);
      final r = client.processInput(p.data,
          remoteIp: p.remoteIp, remotePort: p.remotePort);
      expect(r.isOk, isTrue,
          reason: r.isErr ? 'client error: ${r.error}' : '');
      clientToServer.addAll(r.value.outputPackets);
    }
    rounds++;
  }
}

void main() {
  group('KeyUpdate body wire format', () {
    test('build / parse round-trip for both request values', () {
      for (final req in [
        KeyUpdateRequest.notRequested,
        KeyUpdateRequest.requested,
      ]) {
        final body = buildKeyUpdateBody(req);
        expect(body, equals([req]));
        expect(parseKeyUpdateBody(body), equals(req));
      }
    });

    test('parse rejects wrong length', () {
      expect(parseKeyUpdateBody(Uint8List(0)), isNull);
      expect(parseKeyUpdateBody(Uint8List.fromList([0, 0])), isNull);
    });

    test('parse rejects invalid request value', () {
      expect(parseKeyUpdateBody(Uint8List.fromList([2])), isNull);
      expect(parseKeyUpdateBody(Uint8List.fromList([255])), isNull);
    });

    test('build rejects invalid request value', () {
      expect(() => buildKeyUpdateBody(2), throwsArgumentError);
    });
  });

  group('end-to-end KeyUpdate', () {
    late DtlsV13ClientStateMachine client;
    late DtlsV13ServerStateMachine server;
    late List<Uint8List> serverRx;
    late List<Uint8List> clientRx;

    void connect() {
      client = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      server = DtlsV13ServerStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      serverRx = <Uint8List>[];
      clientRx = <Uint8List>[];
      server.onApplicationData = serverRx.add;
      client.onApplicationData = clientRx.add;

      final start =
          client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5000);
      expect(start.isOk, isTrue);
      _drainHandshake(client, server, initial: start.value.outputPackets);
      expect(client.state, equals(DtlsV13ClientState.connected));
      expect(server.state, equals(DtlsV13ServerState.connected));
    }

    test('client KeyUpdate(notRequested): app data still flows both ways', () {
      connect();

      final ku = client.requestKeyUpdate();
      expect(ku.isOk, isTrue);
      expect(ku.value.outputPackets, hasLength(1));
      // Deliver the KeyUpdate record to the server.
      for (final p in ku.value.outputPackets) {
        final r = server.processInput(p.data,
            remoteIp: p.remoteIp, remotePort: p.remotePort);
        expect(r.isOk, isTrue);
        // notRequested: server does not need to send anything.
        expect(r.value.outputPackets, isEmpty);
      }

      // Client now sends app data under the next-gen tx keys.
      final c2s = client.sendApplicationData(
          Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]));
      expect(c2s.isOk, isTrue);
      for (final p in c2s.value.outputPackets) {
        final r = server.processInput(p.data,
            remoteIp: p.remoteIp, remotePort: p.remotePort);
        expect(r.isOk, isTrue);
      }
      expect(serverRx, hasLength(1));
      expect(serverRx.first, equals([1, 2, 3, 4, 5, 6, 7, 8]));

      // Server still sends under its original keys (no KeyUpdate from server).
      final s2c = server.sendApplicationData(Uint8List.fromList([9, 10, 11]));
      expect(s2c.isOk, isTrue);
      for (final p in s2c.value.outputPackets) {
        final r = client.processInput(p.data,
            remoteIp: p.remoteIp, remotePort: p.remotePort);
        expect(r.isOk, isTrue);
      }
      expect(clientRx, hasLength(1));
      expect(clientRx.first, equals([9, 10, 11]));
    });

    test('server KeyUpdate(requested): client reciprocates on next sendApp',
        () {
      connect();

      final ku = server.requestKeyUpdate(requestPeerUpdate: true);
      expect(ku.isOk, isTrue);

      // Deliver server's KeyUpdate to the client.
      for (final p in ku.value.outputPackets) {
        final r = client.processInput(p.data,
            remoteIp: p.remoteIp, remotePort: p.remotePort);
        expect(r.isOk, isTrue);
        // The client must NOT eagerly emit anything until sendApp is called;
        // RFC 8446 §4.6.3 lets the reciprocation be the next outbound record.
        expect(r.value.outputPackets, isEmpty);
      }

      // Client sends app data; the client SM piggy-backs the reciprocal
      // KeyUpdate ahead of the application record.
      final c2s = client.sendApplicationData(Uint8List.fromList([42]));
      expect(c2s.isOk, isTrue);
      expect(c2s.value.outputPackets, hasLength(2),
          reason: 'expected reciprocal KeyUpdate + the app record');

      // Deliver both records to the server in order.
      for (final p in c2s.value.outputPackets) {
        final r = server.processInput(p.data,
            remoteIp: p.remoteIp, remotePort: p.remotePort);
        expect(r.isOk, isTrue);
      }
      expect(serverRx, hasLength(1));
      expect(serverRx.first, equals([42]));
    });

    test('two consecutive KeyUpdates from the same side bump epoch twice', () {
      connect();

      for (var i = 0; i < 2; i++) {
        final ku = client.requestKeyUpdate();
        expect(ku.isOk, isTrue);
        for (final p in ku.value.outputPackets) {
          final r = server.processInput(p.data,
              remoteIp: p.remoteIp, remotePort: p.remotePort);
          expect(r.isOk, isTrue);
        }
      }

      // After two KeyUpdates the client tx epoch is 5; verify app data
      // continues to decrypt server-side under the rotated rx keys.
      final c2s = client.sendApplicationData(Uint8List.fromList([0xCC]));
      expect(c2s.isOk, isTrue);
      for (final p in c2s.value.outputPackets) {
        final r = server.processInput(p.data,
            remoteIp: p.remoteIp, remotePort: p.remotePort);
        expect(r.isOk, isTrue);
      }
      expect(serverRx, hasLength(1));
      expect(serverRx.first, equals([0xCC]));
    });

    test('requestKeyUpdate before CONNECTED returns StateError', () {
      final c = DtlsV13ClientStateMachine(
        localCert: EcdsaCertificate.selfSigned(),
      );
      final r = c.requestKeyUpdate();
      expect(r.isErr, isTrue);
    });
  });
}
