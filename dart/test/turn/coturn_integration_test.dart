@Tags(['coturn'])
library;

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'coturn_helpers.dart';

void main() {
  group('TURN integration against local coturn', () {
    late CoturnInstance coturn;

    setUp(() async {
      coturn = await startCoturn();
    });

    tearDown(() async {
      await coturn.stop();
    });

    test('Allocate succeeds and emits a relay candidate', () async {
      final pc = PeerConnection(
        configuration: PeerConnectionConfiguration(
          iceServers: [
            IceServer(
              urls: ['turn:127.0.0.1:${coturn.port}?transport=udp'],
              username: coturnUser,
              credential: coturnPass,
            ),
          ],
        ),
      );

      final relayCandidate = pc.onIceCandidate
          .firstWhere((evt) => evt.candidate.contains('typ relay'))
          .timeout(const Duration(seconds: 8));

      // createDataChannel + createOffer + setLocalDescription is enough
      // to spin up the transport and start gathering. The actual SDP we
      // get back is irrelevant here — only the emitted candidates.
      pc.createDataChannel('probe');
      final offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      final evt = await relayCandidate;
      // Relay candidate's IP/port belong to coturn's relay range
      // (49160-49200 per the helper's --min-port / --max-port flags),
      // not the loopback the TURN server itself listens on.
      expect(evt.candidate, contains('typ relay'));
      expect(evt.candidate, contains(' raddr '));
      expect(evt.candidate, contains(' rport '));

      await pc.close();
    }, timeout: const Timeout(Duration(seconds: 15)));
  });
}
