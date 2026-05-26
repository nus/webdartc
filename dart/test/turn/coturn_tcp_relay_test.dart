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
      // SCTP setup forces full ICE→DTLS→SCTP traffic through the TCP
      // control link, exercising both framing directions (STUN
      // responses + DTLS records as Send/Data indications + ChannelData
      // once promotion fires).
      await runRelayHandshake(
        iceServers: [
          IceServer(
            urls: ['turn:127.0.0.1:${coturn.port}?transport=tcp'],
            username: coturnUser,
            credential: coturnPass,
          ),
        ],
        dataChannelLabel: 'relay-tcp-probe',
      );
    }, timeout: const Timeout(Duration(seconds: 45)));
  });
}
