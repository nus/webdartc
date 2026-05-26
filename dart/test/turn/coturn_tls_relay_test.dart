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
      await runRelayHandshake(
        iceServers: [
          IceServer(
            urls: ['turns:127.0.0.1:${coturn.tlsPort}?transport=tcp'],
            username: coturnUser,
            credential: coturnPass,
          ),
        ],
        settingEngine: SettingEngine(
          onBadTurnCertificate: (_) => true,
        ),
        dataChannelLabel: 'relay-tls-probe',
      );
    }, timeout: const Timeout(Duration(seconds: 45)));
  });
}
