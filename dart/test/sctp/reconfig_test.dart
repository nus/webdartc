import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';
import 'package:webdartc/src/sctp/chunk.dart';

import 'sctp_test_helpers.dart';

void main() {
  group('RE-CONFIG chunk (RFC 6525)', () {
    test('Outgoing SSN Reset Request round-trips', () {
      final chunk = SctpReconfigChunk([
        const SctpOutgoingSsnResetRequest(
          requestSeq: 0x11223344,
          responseSeq: 0x55667788,
          lastAssignedTsn: 0x99AABBCC,
          streams: [3, 5, 7],
        ),
      ]);

      final parsed = parseChunks(chunk.encode(), 0);
      expect(parsed, hasLength(1));
      final rc = parsed.first as SctpReconfigChunk;
      expect(rc.type, 0x82);
      final p = rc.parameters.single as SctpOutgoingSsnResetRequest;
      expect(p.requestSeq, 0x11223344);
      expect(p.responseSeq, 0x55667788);
      expect(p.lastAssignedTsn, 0x99AABBCC);
      expect(p.streams, [3, 5, 7]);
    });

    test('Outgoing request with no streams means "all streams"', () {
      final chunk = SctpReconfigChunk([
        const SctpOutgoingSsnResetRequest(
          requestSeq: 1,
          responseSeq: 0,
          lastAssignedTsn: 0,
        ),
      ]);
      final rc = parseChunks(chunk.encode(), 0).single as SctpReconfigChunk;
      final p = rc.parameters.single as SctpOutgoingSsnResetRequest;
      expect(p.streams, isEmpty);
    });

    test('Re-config Response round-trips', () {
      final chunk = SctpReconfigChunk([
        const SctpReconfigResponse(
          responseSeq: 0xDEADBEEF,
          result: SctpReconfigResponse.resultSuccessPerformed,
        ),
      ]);
      final rc = parseChunks(chunk.encode(), 0).single as SctpReconfigChunk;
      final p = rc.parameters.single as SctpReconfigResponse;
      expect(p.responseSeq, 0xDEADBEEF);
      expect(p.result, SctpReconfigResponse.resultSuccessPerformed);
    });

    test('two parameters in one chunk round-trip', () {
      final chunk = SctpReconfigChunk([
        const SctpReconfigResponse(responseSeq: 7, result: 1),
        const SctpOutgoingSsnResetRequest(
            requestSeq: 8, responseSeq: 7, lastAssignedTsn: 9, streams: [2]),
      ]);
      final rc = parseChunks(chunk.encode(), 0).single as SctpReconfigChunk;
      expect(rc.parameters, hasLength(2));
      expect(rc.parameters[0], isA<SctpReconfigResponse>());
      expect(rc.parameters[1], isA<SctpOutgoingSsnResetRequest>());
    });
  });

  group('SctpStateMachine stream reset', () {
    test('resetStreams fails before the association is established', () {
      final sctp = SctpStateMachine(isClient: true);
      expect(sctp.resetStreams([0]).isErr, isTrue);
    });

    test('reset round-trips and both peers observe the stream reset', () {
      final (client, server) = establishSctpPair();

      final clientResets = <int>[];
      final serverResets = <int>[];
      client.onStreamReset = clientResets.add;
      server.onStreamReset = serverResets.add;

      // Client closes stream 0 → emits an Outgoing SSN Reset Request.
      final start = client.resetStreams([0]);
      expect(start.isOk, isTrue);
      final firstPkt = start.value.outputPackets.single;
      expect(firstPkt.data[12], 0x82, reason: 'RE-CONFIG chunk type');

      // Drive every resulting packet between the two peers until quiescent.
      _pump(client, server, start.value.outputPackets);

      expect(clientResets, [0]);
      expect(serverResets, [0]);
    });

    test('a duplicate reset request is answered without re-firing the reset',
        () {
      final (client, server) = establishSctpPair();
      final serverResets = <int>[];
      server.onStreamReset = serverResets.add;

      final start = client.resetStreams([0]);
      final reconfig = start.value.outputPackets.single.data;
      final ip = IpAddress.parse('127.0.0.1');

      // Deliver the same request twice.
      final first =
          server.processInput(reconfig, remoteIp: ip, remotePort: 5000);
      final second =
          server.processInput(reconfig, remoteIp: ip, remotePort: 5000);

      expect(first.isOk, isTrue);
      expect(second.isOk, isTrue);
      // Both produce a response packet…
      expect(first.value.outputPackets, isNotEmpty);
      expect(second.value.outputPackets, isNotEmpty);
      // …but the reset is reported exactly once.
      expect(serverResets, [0]);
    });
  });
}

/// Feed every output packet from one peer to the other, recursively, until no
/// peer produces further output.
void _pump(
  SctpStateMachine client,
  SctpStateMachine server,
  List<OutputPacket> initial,
) {
  final ip = IpAddress.parse('127.0.0.1');
  // Worklist of (receiver, bytes). `initial` came from the client, so it is
  // destined for the server.
  final queue = <(SctpStateMachine, Uint8List)>[
    for (final p in initial) (server, p.data),
  ];
  var guard = 0;
  while (queue.isNotEmpty) {
    if (guard++ > 100) { fail('reset did not converge (possible loop)'); }
    final (to, data) = queue.removeAt(0);
    final r = to.processInput(data, remoteIp: ip, remotePort: 5000);
    expect(r.isOk, isTrue);
    final other = identical(to, client) ? server : client;
    for (final p in r.value.outputPackets) {
      queue.add((other, p.data));
    }
  }
}
