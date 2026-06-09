import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'loopback.dart';

void main() {
  group('PeerConnection.getConfiguration', () {
    test('returns the configuration the connection was created with', () async {
      const config = PeerConnectionConfiguration();
      final pc = PeerConnection(configuration: config);
      expect(pc.getConfiguration(), same(config));
      await pc.close();
    });
  });

  group('PeerConnection.iceGatheringState', () {
    test('transitions new → gathering → complete and fires the event',
        () async {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        settingEngine: kLoopbackSetting,
      );
      try {
        expect(pc.iceGatheringState, IceGatheringState.newState);

        final states = <IceGatheringState>[];
        pc.onIceGatheringStateChange.listen(states.add);
        final reachedComplete = pc.onIceGatheringStateChange
            .firstWhere((s) => s == IceGatheringState.complete);

        // setLocalDescription begins ICE gathering.
        pc.createDataChannel('probe');
        final offer = await pc.createOffer();
        await pc.setLocalDescription(offer);

        await reachedComplete.timeout(const Duration(seconds: 10));
        expect(pc.iceGatheringState, IceGatheringState.complete);
        expect(
          states,
          containsAllInOrder(
              [IceGatheringState.gathering, IceGatheringState.complete]),
        );
      } finally {
        await pc.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });
}
