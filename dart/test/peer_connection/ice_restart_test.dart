import 'dart:async';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'loopback.dart';

String? _ufrag(String sdp) =>
    RegExp(r'a=ice-ufrag:(\S+)').firstMatch(sdp)?.group(1);

void main() {
  group('PeerConnection.restartIce', () {
    test('regenerates credentials and re-establishes connectivity', () async {
      DataChannel? dcA;
      DataChannel? dcB;
      final (pcA, pcB) = await handshakeLoopback(
        configureA: (pc) => dcA = pc.createDataChannel('chat'),
        configureB: (pc) => pc.onDataChannel.listen((e) => dcB = e.channel),
      );

      try {
        if (dcA!.readyState != DataChannelState.open) {
          await dcA!.onOpen.first.timeout(const Duration(seconds: 15));
        }
        expect(dcB, isNotNull);

        // Data flows before the restart.
        final before = dcB!.onMessage.first;
        dcA!.send('before');
        expect((await before.timeout(const Duration(seconds: 10))).text,
            'before');

        final origUfrag = _ufrag(pcA.localDescription!.sdp);

        // ICE restart on the offerer → new credentials in the next offer.
        pcA.restartIce();
        final offer2 = await pcA.createOffer();
        final newUfrag = _ufrag(offer2.sdp);
        expect(newUfrag, isNotNull);
        expect(newUfrag, isNot(origUfrag));

        // Renegotiate (the answerer auto-restarts on the changed ufrag).
        await pcA.setLocalDescription(offer2);
        await pcB.setRemoteDescription(offer2);
        final answer2 = await pcB.createAnswer();
        expect(_ufrag(answer2.sdp), isNot(origUfrag)); // answerer also restarted
        await pcB.setLocalDescription(answer2);
        await pcA.setRemoteDescription(answer2);

        // Data flows again over the freshly-validated ICE pair. Re-send until
        // it lands — the new pair takes a moment to validate after the restart.
        final after = dcB!.onMessage.firstWhere((m) => m.text == 'after');
        var delivered = false;
        unawaited(after.then((_) => delivered = true));
        for (var i = 0; i < 60 && !delivered; i++) {
          dcA!.send('after');
          await Future<void>.delayed(const Duration(milliseconds: 250));
        }
        expect((await after.timeout(const Duration(seconds: 5))).text, 'after');
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 60)));
  });
}
