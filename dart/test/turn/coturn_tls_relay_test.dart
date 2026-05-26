@Tags(['coturn'])
library;

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'coturn_helpers.dart';

void main() {
  group('TURN TLS control link', () {
    late CoturnInstance coturn;

    setUp(() async {
      coturn = await startCoturn(withTls: true);
    });

    tearDown(() async {
      await coturn.stop();
    });

    test('relay-only data channel reaches connected over `turns:`',
        () async {
      // coturn is serving a freshly-minted self-signed cert (CN=localhost)
      // we have no way to chain into the platform trust store — accept
      // any cert for this loopback test. Production code must leave
      // `onBadTurnCertificate` null.
      final setting = SettingEngine(
        onBadTurnCertificate: (_) => true,
      );

      final iceServers = [
        IceServer(
          urls: ['turns:127.0.0.1:${coturn.tlsPort}?transport=tcp'],
          username: coturnUser,
          credential: coturnPass,
        ),
      ];
      final config = PeerConnectionConfiguration(
        iceServers: iceServers,
        iceTransportPolicy: IceTransportPolicy.relay,
      );
      final pcA = PeerConnection(configuration: config, settingEngine: setting);
      final pcB = PeerConnection(configuration: config, settingEngine: setting);

      try {
        forwardIceCandidates(pcA, pcB);
        forwardIceCandidates(pcB, pcA);

        pcA.createDataChannel('relay-tls-probe');

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
