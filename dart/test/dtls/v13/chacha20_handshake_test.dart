// End-to-end DTLS 1.3 handshake test where the negotiated cipher suite is
// `TLS_CHACHA20_POLY1305_SHA256` (0x1303). The client offers ChaCha20 only
// so the server is forced to pick it; we then drive the handshake to
// CONNECTED, exchange application data, and confirm record-layer
// ChaCha20-Poly1305 + ChaCha20-based sequence-number protection are wired.

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/core/state_machine.dart';
import 'package:webdartc/crypto/ecdsa.dart';
import 'package:webdartc/dtls/v13/cipher_suite.dart';
import 'package:webdartc/dtls/v13/client_state_machine.dart';
import 'package:webdartc/dtls/v13/state_machine.dart';

void main() {
  void drainLoopback(
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
        final r = server.processInput(
          p.data,
          remoteIp: p.remoteIp,
          remotePort: p.remotePort,
        );
        expect(r.isOk, isTrue,
            reason: r.isErr ? 'server error: ${r.error}' : '');
        serverToClient.addAll(r.value.outputPackets);
      }
      while (serverToClient.isNotEmpty) {
        final p = serverToClient.removeAt(0);
        final r = client.processInput(
          p.data,
          remoteIp: p.remoteIp,
          remotePort: p.remotePort,
        );
        expect(r.isOk, isTrue,
            reason: r.isErr ? 'client error: ${r.error}' : '');
        clientToServer.addAll(r.value.outputPackets);
      }
      rounds++;
    }
  }

  test('full handshake reaches CONNECTED with TLS_CHACHA20_POLY1305_SHA256',
      () {
    final client = DtlsV13ClientStateMachine(
      localCert: EcdsaCertificate.selfSigned(),
      offeredCipherSuites: const <int>[0x1303], // ChaCha20-only offer
    );
    final server = DtlsV13ServerStateMachine(
      localCert: EcdsaCertificate.selfSigned(),
    );

    final start = client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5000);
    expect(start.isOk, isTrue);
    drainLoopback(client, server, initial: start.value.outputPackets);

    expect(client.state, equals(DtlsV13ClientState.connected));
    expect(server.state, equals(DtlsV13ServerState.connected));
    expect(client.cipherSuite, same(TlsV13CipherSuite.chacha20Poly1305Sha256));
    expect(server.cipherSuite, same(TlsV13CipherSuite.chacha20Poly1305Sha256));
    expect(client.exporterMasterSecret, equals(server.exporterMasterSecret));
  });

  test('application data round-trips both directions over ChaCha20', () {
    final client = DtlsV13ClientStateMachine(
      localCert: EcdsaCertificate.selfSigned(),
      offeredCipherSuites: const <int>[0x1303],
    );
    final server = DtlsV13ServerStateMachine(
      localCert: EcdsaCertificate.selfSigned(),
    );

    final fromServerToClient = <Uint8List>[];
    final fromClientToServer = <Uint8List>[];
    client.onApplicationData = fromServerToClient.add;
    server.onApplicationData = fromClientToServer.add;

    final start = client.startHandshake(remoteIp: '127.0.0.1', remotePort: 5000);
    expect(start.isOk, isTrue);
    drainLoopback(client, server, initial: start.value.outputPackets);
    expect(client.state, equals(DtlsV13ClientState.connected));

    // Server → client.
    final s2c = server.sendApplicationData(
      Uint8List.fromList(List<int>.generate(64, (i) => 0x10 ^ i)),
    );
    expect(s2c.isOk, isTrue);
    for (final p in s2c.value.outputPackets) {
      final r = client.processInput(
        p.data,
        remoteIp: p.remoteIp,
        remotePort: p.remotePort,
      );
      expect(r.isOk, isTrue);
    }
    expect(fromServerToClient.length, equals(1));
    expect(fromServerToClient.first.length, equals(64));

    // Client → server.
    final c2s = client.sendApplicationData(
      Uint8List.fromList(List<int>.generate(48, (i) => 0xA5 ^ i)),
    );
    expect(c2s.isOk, isTrue);
    for (final p in c2s.value.outputPackets) {
      final r = server.processInput(
        p.data,
        remoteIp: p.remoteIp,
        remotePort: p.remotePort,
      );
      expect(r.isOk, isTrue);
    }
    expect(fromClientToServer.length, equals(1));
    expect(fromClientToServer.first.length, equals(48));
  });
}
