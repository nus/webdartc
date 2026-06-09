import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'loopback.dart';

void main() {
  group('DataChannel open (webdartc↔webdartc loopback)', () {
    test('both peers open the channel and data flows', () async {
      DataChannel? dcA;
      DataChannel? dcB;
      final (pcA, pcB) = await handshakeLoopback(
        configureA: (pc) => dcA = pc.createDataChannel('chat'),
        configureB: (pc) => pc.onDataChannel.listen((e) => dcB = e.channel),
      );

      try {
        // Opener (A) reaches `open` once the DCEP OPEN/ACK round-trips.
        if (dcA!.readyState != DataChannelState.open) {
          await dcA!.onOpen.first.timeout(const Duration(seconds: 15));
        }
        expect(dcA!.readyState, DataChannelState.open);

        // Answerer (B) received the channel via ondatachannel.
        expect(dcB, isNotNull);
        expect(dcB!.label, 'chat');

        // Data flows A→B over the freshly-opened channel.
        final fromA = dcB!.onMessage.first;
        dcA!.send('hello');
        final msg = await fromA.timeout(const Duration(seconds: 10));
        expect(msg.text, 'hello');
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));
  });
}
