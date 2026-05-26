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
  });
}
