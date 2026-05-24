@Tags(['coturn'])
library;

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'coturn_helpers.dart';

void main() {
  group('TURN channel promotion', () {
    late CoturnInstance coturn;

    setUp(() async {
      coturn = await startCoturn();
    });

    tearDown(() async {
      await coturn.stop();
    });

    test('peer with sustained traffic is auto-promoted to ChannelData',
        () async {
      final iceServers = [
        IceServer(
          urls: ['turn:127.0.0.1:${coturn.port}?transport=udp'],
          username: coturnUser,
          credential: coturnPass,
        ),
      ];
      final pcA = PeerConnection(
        configuration: PeerConnectionConfiguration(iceServers: iceServers),
      );
      final pcB = PeerConnection(
        configuration: PeerConnectionConfiguration(iceServers: iceServers),
      );

      try {
        pcA.onIceCandidate.listen((evt) => maybeForwardRelay(evt, pcB));
        pcB.onIceCandidate.listen((evt) => maybeForwardRelay(evt, pcA));

        pcA.createDataChannel('promote-probe');

        final offer = await pcA.createOffer();
        await pcA.setLocalDescription(offer);
        await pcB.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: stripHostAddress(offer.sdp)));
        final answer = await pcB.createAnswer();
        await pcB.setLocalDescription(answer);
        await pcA.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.answer,
            sdp: stripHostAddress(answer.sdp)));

        await Future.wait([
          pcA.onConnectionStateChange
              .firstWhere((s) => s == PeerConnectionState.connected),
          pcB.onConnectionStateChange
              .firstWhere((s) => s == PeerConnectionState.connected),
        ]).timeout(const Duration(seconds: 25));

        // Reaching connected required ~10+ wrapped sends per side (ICE
        // checks + DTLS handshake + SCTP setup) so the promotion
        // threshold has fired by now; the ChannelBind ack lands one
        // RTT after the threshold trips — wait briefly for it.
        await _eventuallyTrue(
          () => _allAllocationsHaveBoundChannel([pcA, pcB]),
          timeout: const Duration(seconds: 5),
        );

        for (final pc in [pcA, pcB]) {
          expect(pc.turnAllocations, isNotEmpty);
          for (final allocation in pc.turnAllocations) {
            expect(allocation.channelCount, greaterThan(0),
                reason:
                    'allocation against ${allocation.serverIp} should have '
                    'promoted at least one peer to ChannelData by now');
          }
        }
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));
  });
}

bool _allAllocationsHaveBoundChannel(List<PeerConnection> pcs) {
  for (final pc in pcs) {
    if (pc.turnAllocations.isEmpty) return false;
    for (final allocation in pc.turnAllocations) {
      if (allocation.channelCount == 0) return false;
    }
  }
  return true;
}

Future<void> _eventuallyTrue(bool Function() predicate,
    {required Duration timeout}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    if (predicate()) return;
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
  throw StateError('predicate stayed false for $timeout');
}
