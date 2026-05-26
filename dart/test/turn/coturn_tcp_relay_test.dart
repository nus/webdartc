@Tags(['coturn'])
library;

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'coturn_helpers.dart';

void main() {
  group('TURN TCP control link', () {
    late CoturnInstance coturn;

    setUp(() async {
      coturn = await startCoturn();
    });

    tearDown(() async {
      await coturn.stop();
    });

    test('relay-only data channel reaches connected over `?transport=tcp`',
        () async {
      final iceServers = [
        IceServer(
          urls: ['turn:127.0.0.1:${coturn.port}?transport=tcp'],
          username: coturnUser,
          credential: coturnPass,
        ),
      ];
      final config = PeerConnectionConfiguration(
        iceServers: iceServers,
        iceTransportPolicy: IceTransportPolicy.relay,
      );
      final pcA = PeerConnection(configuration: config);
      final pcB = PeerConnection(configuration: config);

      try {
        forwardIceCandidates(pcA, pcB);
        forwardIceCandidates(pcB, pcA);

        // SCTP setup forces full ICE→DTLS→SCTP traffic through the TCP
        // control link, which exercises both framing directions
        // (STUN check responses + DTLS records relayed as Send/Data
        // indications + ChannelData once promotion fires).
        pcA.createDataChannel('relay-tcp-probe');

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
        ]).timeout(const Duration(seconds: 25));

        // Each PC should own exactly one TCP-backed allocation; the
        // relayed candidate is the only candidate ICE could have
        // nominated under relay-only.
        for (final pc in [pcA, pcB]) {
          expect(pc.turnAllocations, hasLength(1));
        }
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));
  });
}
