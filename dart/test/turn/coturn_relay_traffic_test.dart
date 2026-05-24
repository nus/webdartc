@Tags(['coturn'])
library;

import 'dart:async';
import 'dart:convert';

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
      // End-to-end proof of the relay-traffic plumbing: each PC's
      // outgoing packets get wrapped into TURN Send indications, the
      // peer's TURN allocation unwraps them, the transport
      // re-dispatches as if direct, and the full STUN/DTLS/SCTP stack
      // completes — all forced through coturn because the test feeds
      // only relay candidates across the signaling channel and scrubs
      // the SDP's default address.
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
        pcA.onIceCandidate.listen((evt) => _maybeForwardRelay(evt, pcB));
        pcB.onIceCandidate.listen((evt) => _maybeForwardRelay(evt, pcA));

        // A data channel forces SCTP setup over DTLS, which in turn
        // exercises the wrap path end-to-end (ICE checks → DTLS
        // handshake → SCTP INIT/COOKIE) without needing the DCEP
        // ACK semantics that the in-band open expects.
        pcA.createDataChannel('relay-probe');

        final offer = await pcA.createOffer();
        await pcA.setLocalDescription(offer);
        await pcB.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: _stripHostAddress(offer.sdp)));
        final answer = await pcB.createAnswer();
        await pcB.setLocalDescription(answer);
        await pcA.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.answer,
            sdp: _stripHostAddress(answer.sdp)));

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

void _maybeForwardRelay(PeerConnectionIceEvent evt, PeerConnection to) {
  if (!evt.candidate.contains('typ relay')) return;
  to.addIceCandidate(IceCandidateInit(
    candidate: evt.candidate,
    sdpMid: evt.sdpMid,
    sdpMLineIndex: evt.sdpMLineIndex,
  ));
}

/// Force the relay-only test: scrub the SDP so the peer can't fall
/// back to any non-relay path.
///   - default connection address → 0.0.0.0 / port 9 (RFC 8839 §5.1)
///   - drop every `a=candidate:` line that isn't `typ relay`
///   (host candidates are emitted into the offer SDP synchronously by
///   the SdpBuilder; trickle-side filtering alone isn't enough.)
String _stripHostAddress(String sdp) {
  final out = StringBuffer();
  for (final line in const LineSplitter().convert(sdp)) {
    if (line.startsWith('c=IN IP4 ')) {
      out.writeln('c=IN IP4 0.0.0.0');
    } else if (line.startsWith('m=')) {
      final parts = line.split(' ');
      if (parts.length >= 4) {
        parts[1] = '9';
        out.writeln(parts.join(' '));
      } else {
        out.writeln(line);
      }
    } else if (line.startsWith('a=candidate:') &&
        !line.contains('typ relay')) {
      // drop
    } else {
      out.writeln(line);
    }
  }
  return out.toString();
}
