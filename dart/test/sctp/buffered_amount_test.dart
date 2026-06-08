import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

import 'sctp_test_helpers.dart';

/// Deliver [packet] to [to] and return its output packets.
List<OutputPacket> _deliver(SctpStateMachine to, Uint8List packet, int fromPort) {
  final r = to.processInput(packet,
      remoteIp: IpAddress.parse('127.0.0.1'), remotePort: fromPort);
  expect(r.isOk, isTrue);
  return r.value.outputPackets;
}

void main() {
  group('SctpStateMachine.onBytesAcked', () {
    const clientPort = 5000;
    const serverPort = 5001;

    test('reports acked application bytes per stream on SACK', () {
      final (client, server) = establishSctpPair();
      final acked = <(int, int)>[];
      client.onBytesAcked = (sid, bytes) => acked.add((sid, bytes));

      final out = client.sendData(
          data: Uint8List(200), streamId: 3, ordered: true);
      expect(out.isOk, isTrue);
      // Server receives the DATA and replies with a SACK.
      final sack = _deliver(server, out.value.outputPackets.single.data, clientPort);
      // Client processes the SACK → onBytesAcked fires.
      _deliver(client, sack.single.data, serverPort);

      expect(acked, [(3, 200)]);
    });

    test('an empty message acks zero application bytes (no callback)', () {
      final (client, server) = establishSctpPair();
      final acked = <(int, int)>[];
      client.onBytesAcked = (sid, bytes) => acked.add((sid, bytes));

      // RFC 8831 §6.6 empty message: 1 padding byte on the wire, 0 app bytes.
      final out = client.sendData(
          data: Uint8List(0),
          streamId: 1,
          ordered: true,
          ppid: SctpPpid.webrtcStringEmpty);
      final sack = _deliver(server, out.value.outputPackets.single.data, clientPort);
      _deliver(client, sack.single.data, serverPort);

      expect(acked, isEmpty);
    });

    test('separates acked bytes by stream', () {
      final (client, server) = establishSctpPair();
      final acked = <int, int>{};
      client.onBytesAcked =
          (sid, bytes) => acked[sid] = (acked[sid] ?? 0) + bytes;

      for (final (sid, len) in [(2, 100), (4, 250)]) {
        final out = client.sendData(
            data: Uint8List(len), streamId: sid, ordered: true);
        final sack =
            _deliver(server, out.value.outputPackets.single.data, clientPort);
        _deliver(client, sack.single.data, serverPort);
      }

      expect(acked, {2: 100, 4: 250});
    });
  });
}
