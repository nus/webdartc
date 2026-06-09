import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import 'loopback.dart';

void main() {
  group('PeerConnection.connectionState', () {
    test('starts in the `new` state before any transport begins', () async {
      final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
      expect(pc.connectionState, PeerConnectionState.newState);
      await pc.close();
      expect(pc.connectionState, PeerConnectionState.closed);
    });
  });

  group('PeerConnection.setConfiguration', () {
    test('replaces iceServers but rejects immutable policy changes', () async {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(
          bundlePolicy: 'max-bundle',
          rtcpMuxPolicy: 'require',
        ),
      );
      try {
        const updated = PeerConnectionConfiguration(
          iceServers: [IceServer(urls: ['stun:stun.example.org:3478'])],
          bundlePolicy: 'max-bundle',
          rtcpMuxPolicy: 'require',
        );
        pc.setConfiguration(updated);
        expect(pc.getConfiguration(), same(updated));
        expect(pc.getConfiguration().iceServers, hasLength(1));

        expect(
          () => pc.setConfiguration(const PeerConnectionConfiguration(
              bundlePolicy: 'balanced')),
          throwsStateError,
        );
        expect(
          () => pc.setConfiguration(const PeerConnectionConfiguration(
              rtcpMuxPolicy: 'negotiate')),
          throwsStateError,
        );
      } finally {
        await pc.close();
      }
      expect(
        () => pc.setConfiguration(const PeerConnectionConfiguration()),
        throwsStateError,
      );
    });
  });

  group('PeerConnection current/pending descriptions', () {
    test('are null before negotiation and settle after the handshake',
        () async {
      final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
      expect(pc.currentLocalDescription, isNull);
      expect(pc.pendingLocalDescription, isNull);
      await pc.close();
    });

    test('an applied offer is pending until the answer arrives', () async {
      DataChannel? dc;
      final (pcA, pcB) = await handshakeLoopback(
        configureA: (pc) => dc = pc.createDataChannel('chat'),
        configureB: (pc) => pc.onDataChannel.listen((_) {}),
      );
      try {
        expect(dc, isNotNull);
        // After the full exchange both sides are stable: descriptions current,
        // nothing pending.
        expect(pcA.currentLocalDescription, isNotNull);
        expect(pcA.currentRemoteDescription, isNotNull);
        expect(pcA.pendingLocalDescription, isNull);
        expect(pcA.pendingRemoteDescription, isNull);

        expect(pcB.currentLocalDescription, isNotNull);
        expect(pcB.currentRemoteDescription, isNotNull);
        expect(pcB.pendingLocalDescription, isNull);
        expect(pcB.pendingRemoteDescription, isNull);
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('offer is pending mid-negotiation, current once answered', () async {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        settingEngine: kLoopbackSetting,
      );
      try {
        pc.createDataChannel('probe');
        final offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        // Local offer is pending; not yet current.
        expect(pc.pendingLocalDescription, isNotNull);
        expect(pc.currentLocalDescription, isNull);
      } finally {
        await pc.close();
      }
    });
  });

  group('PeerConnection.onNegotiationNeeded', () {
    test('fires after createDataChannel while stable', () async {
      final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
      try {
        final fired = pc.onNegotiationNeeded.first;
        pc.createDataChannel('chat');
        await fired.timeout(const Duration(seconds: 2));
      } finally {
        await pc.close();
      }
    });

    test('fires after addTransceiver while stable', () async {
      final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
      try {
        final fired = pc.onNegotiationNeeded.first;
        pc.addTransceiver('audio');
        await fired.timeout(const Duration(seconds: 2));
      } finally {
        await pc.close();
      }
    });

    test('coalesces a burst of additions into a single event', () async {
      final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
      try {
        var count = 0;
        pc.onNegotiationNeeded.listen((_) => count++);
        pc.addTransceiver('audio');
        pc.addTransceiver('video');
        pc.createDataChannel('chat');
        await Future<void>.delayed(const Duration(milliseconds: 50));
        expect(count, 1);
      } finally {
        await pc.close();
      }
    });

    test('fires again after a completed negotiation', () async {
      final (pcA, pcB) = await handshakeLoopback(
        configureA: (pc) => pc.createDataChannel('chat'),
        configureB: (pc) => pc.onDataChannel.listen((_) {}),
      );
      try {
        // The handshake completed the first negotiation and cleared the flag;
        // a fresh change must raise negotiationneeded again.
        final fired = pcA.onNegotiationNeeded.first;
        pcA.addTransceiver('audio');
        await fired.timeout(const Duration(seconds: 2));
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  group('PeerConnection.onIceCandidateError', () {
    test('fires when a STUN server never answers (timeout → 701)', () async {
      // RFC 5737 TEST-NET-1: routable nowhere, so the gather request times out.
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(
          iceServers: [IceServer(urls: ['stun:192.0.2.1:3478'])],
        ),
        settingEngine: kLoopbackSetting,
      );
      try {
        final err = pc.onIceCandidateError.first;
        pc.createDataChannel('probe');
        final offer = await pc.createOffer();
        await pc.setLocalDescription(offer); // begins gathering
        final e = await err.timeout(const Duration(seconds: 8));
        expect(e.url, 'stun:192.0.2.1:3478');
        expect(e.errorCode, 701);
      } finally {
        await pc.close();
      }
    }, timeout: const Timeout(Duration(seconds: 20)));
  });
}
