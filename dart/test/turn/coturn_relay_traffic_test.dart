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
      // Forced relay-only: only relay candidates cross the signaling
      // channel and the SDP default address is scrubbed, so direct
      // host pairs can't form. Both peers reaching connected proves
      // every layer (ICE / DTLS / SCTP) survives the TURN round-trip.
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

        // A data channel forces SCTP setup over DTLS, which in turn
        // exercises the wrap path end-to-end (ICE checks → DTLS
        // handshake → SCTP INIT/COOKIE) without needing the DCEP
        // ACK semantics that the in-band open expects.
        pcA.createDataChannel('relay-probe');

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
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));
  });
}
