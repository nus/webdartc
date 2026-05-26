@Tags(['coturn'])
library;

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'coturn_helpers.dart';

void main() {
  group('TURN relay-only data channel', () {
    late CoturnInstance coturn;

    setUp(() async {
      coturn = await startCoturn();
    });

    tearDown(() async {
      await coturn.stop();
    });

    test('two PeerConnections reach connected over a relay-only path',
        () async {
      // Forced relay-only via `iceTransportPolicy.relay` (set inside
      // the shared helper). Both peers reaching connected proves every
      // layer (ICE / DTLS / SCTP) survives the TURN round-trip — the
      // data channel pulls in SCTP, which only forms over DTLS, which
      // only forms once ICE has nominated a pair.
      await runRelayHandshake(
        iceServers: [
          IceServer(
            urls: ['turn:127.0.0.1:${coturn.port}?transport=udp'],
            username: coturnUser,
            credential: coturnPass,
          ),
        ],
        dataChannelLabel: 'relay-probe',
      );
    }, timeout: const Timeout(Duration(seconds: 45)));

    test('getStats surfaces relay-only flow accurately', () async {
      // Same handshake, but inspect getStats() while the PCs are
      // connected. Under `iceTransportPolicy.relay` ICE can only have
      // nominated a pair whose local candidate is `relay`-typed and
      // whose bytes flowed through the TURN allocation.
      await runRelayHandshake(
        iceServers: [
          IceServer(
            urls: ['turn:127.0.0.1:${coturn.port}?transport=udp'],
            username: coturnUser,
            credential: coturnPass,
          ),
        ],
        dataChannelLabel: 'stats-relay-probe',
        whileConnected: (pcA, pcB) async {
          final reportA = await pcA.getStats();
          final reportB = await pcB.getStats();

          // Transport counters must have advanced both directions on
          // both peers — every ICE check, DTLS record, and SCTP packet
          // crossed the TURN allocation, so the byte counts are non-
          // trivially > 0.
          for (final report in [reportA, reportB]) {
            final transport = report['transport'] as TransportStats;
            expect(transport.bytesSent, greaterThan(0));
            expect(transport.bytesReceived, greaterThan(0));
            expect(transport.packetsSent, greaterThan(0));
            expect(transport.packetsReceived, greaterThan(0));
            expect(transport.selectedCandidatePairId, isNotNull);

            // The nominated pair's local side is the TURN-derived
            // relay candidate, never a host or srflx — relay-only
            // policy guarantees that's the only thing ICE could pair.
            final pair = report[transport.selectedCandidatePairId!]
                as CandidatePairStats;
            final local = report[pair.localCandidateId] as CandidateStats;
            expect(local.candidateType, IceCandidateType.relay);
          }

          // Outbound activity is non-trivial — coturn relay overhead
          // (Send indication / ChannelData wrap) adds on top of the
          // payloads, so even a quick handshake should clear ~1 KB
          // each way.
          expect((reportA['transport'] as TransportStats).bytesSent,
              greaterThan(1024));
        },
      );
    }, timeout: const Timeout(Duration(seconds: 45)));
  });
}
