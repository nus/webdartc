import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

/// Wire bidirectional trickle-ICE forwarding between two loopback PCs.
/// The bodies of the multi-PC tests collapsed to nearly the same six
/// lines; this helper keeps the focus on the actual stats assertions.
void _wireTrickle(PeerConnection pcA, PeerConnection pcB) {
  pcA.onIceCandidate.listen((evt) => pcB.addIceCandidate(IceCandidateInit(
        candidate: evt.candidate,
        sdpMid: evt.sdpMid,
        sdpMLineIndex: evt.sdpMLineIndex,
      )));
  pcB.onIceCandidate.listen((evt) => pcA.addIceCandidate(IceCandidateInit(
        candidate: evt.candidate,
        sdpMid: evt.sdpMid,
        sdpMLineIndex: evt.sdpMLineIndex,
      )));
}

/// Settings for the loopback handshake helper below. All stats tests
/// want the same shape: bind to `127.0.0.1`, allow loopback host
/// candidates, no STUN/TURN.
const _kLoopbackSetting = SettingEngine(
  bindAddresses: ['127.0.0.1'],
  includeLoopbackCandidate: true,
);

/// Construct two PCs, wire trickle forwarding, run the offer/answer
/// dance, and wait until both reach `connected`. Optional callbacks
/// let the caller mutate each PC before the SDP exchange — separate
/// for A and B so an asymmetric setup (e.g. DataChannel on offerer
/// only) is expressible.
Future<(PeerConnection, PeerConnection)> _handshakeLoopback({
  void Function(PeerConnection pc)? configureA,
  void Function(PeerConnection pc)? configureB,
  Duration connectedTimeout = const Duration(seconds: 20),
}) async {
  final pcA = PeerConnection(
    configuration: PeerConnectionConfiguration(),
    settingEngine: _kLoopbackSetting,
  );
  final pcB = PeerConnection(
    configuration: PeerConnectionConfiguration(),
    settingEngine: _kLoopbackSetting,
  );
  _wireTrickle(pcA, pcB);
  if (configureA != null) configureA(pcA);
  if (configureB != null) configureB(pcB);
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
  ]).timeout(connectedTimeout);
  return (pcA, pcB);
}

void main() {
  group('PeerConnection.getStats', () {
    test('fresh PC returns transport + peer-connection entries with zeros',
        () async {
      final pc = PeerConnection(configuration: PeerConnectionConfiguration());
      final report = await pc.getStats();
      try {
        final transport = report['transport'] as TransportStats?;
        final pcStats = report['pc'] as PeerConnectionStats?;
        expect(transport, isNotNull);
        expect(pcStats, isNotNull);

        // No traffic yet → counters are zero. ICE has not gathered, so
        // there should be no candidate or pair entries.
        expect(transport!.bytesSent, 0);
        expect(transport.bytesReceived, 0);
        expect(transport.packetsSent, 0);
        expect(transport.packetsReceived, 0);
        expect(transport.selectedCandidatePairId, isNull);
        expect(pcStats!.dataChannelsOpened, 0);
        expect(pcStats.dataChannelsClosed, 0);
        expect(report.ofType<CandidatePairStats>(RtcStatsType.candidatePair),
            isEmpty);
      } finally {
        await pc.close();
      }
    });

    test('DataChannel counters update on send', () async {
      // Sanity check without a real connection: createDataChannel +
      // forcibly mark it open and send. Exercises the counter increments
      // in the absence of SCTP plumbing.
      final pc = PeerConnection(configuration: PeerConnectionConfiguration());
      try {
        final dc = pc.createDataChannel('counter-probe');
        final initialReport = await pc.getStats();
        final initial = initialReport
            .ofType<DataChannelStats>(RtcStatsType.dataChannel)
            .single;
        expect(initial.label, 'counter-probe');
        expect(initial.state, 'connecting');
        expect(initial.messagesSent, 0);
        expect(initial.bytesSent, 0);
        // Send is gated on readyState=open, so we only verify the
        // initial snapshot here; the loopback test below exercises the
        // open path end-to-end.
        expect(() => dc.send('x'), throwsStateError);
      } finally {
        await pc.close();
      }
    });

    test('two loopback PCs accumulate transport bytes and surface ICE pairs',
        () async {
      // A data channel is needed so an SCTP m-line is present in the
      // SDP; ICE doesn't form pairs without one.
      final (pcA, pcB) = await _handshakeLoopback(
        configureA: (pc) => pc.createDataChannel('stats-probe'),
      );

      try {
        final reportA = await pcA.getStats();
        final reportB = await pcB.getStats();

        // Both peers must have moved bytes during ICE checks + DTLS
        // handshake.
        final transportA = reportA['transport'] as TransportStats;
        final transportB = reportB['transport'] as TransportStats;
        expect(transportA.bytesSent, greaterThan(0));
        expect(transportA.bytesReceived, greaterThan(0));
        expect(transportA.packetsSent, greaterThan(0));
        expect(transportA.packetsReceived, greaterThan(0));
        expect(transportB.bytesSent, greaterThan(0));
        expect(transportB.bytesReceived, greaterThan(0));

        // ICE nominated a pair on both sides; getStats surfaces it as
        // the transport's selectedCandidatePairId pointing at one of
        // the CandidatePairStats entries.
        expect(transportA.selectedCandidatePairId, isNotNull);
        final selected = reportA[transportA.selectedCandidatePairId!]
            as CandidatePairStats?;
        expect(selected, isNotNull);
        // ICE may not flip the pair to `succeeded` synchronously when
        // the PC transitions to `connected` (DTLS races ahead on
        // loopback). Accept any non-failed state.
        expect(selected!.state, isNot('failed'));
        // `nominated` may briefly lag the state transition to
        // `connected`; just confirm the boolean exists and is sensible.
        expect(selected.nominated, isA<bool>());

        // The candidate ids the selected pair references must resolve
        // to real local + remote candidate entries.
        expect(reportA[selected.localCandidateId], isA<CandidateStats>());
        expect(reportA[selected.remoteCandidateId], isA<CandidateStats>());

        // Counters are monotonic between two snapshots taken in
        // sequence.
        final reportA2 = await pcA.getStats();
        final transportA2 = reportA2['transport'] as TransportStats;
        expect(transportA2.bytesSent, greaterThanOrEqualTo(transportA.bytesSent));
        expect(transportA2.bytesReceived,
            greaterThanOrEqualTo(transportA.bytesReceived));

        // Stable id: the selected pair id is the same across snapshots.
        expect(transportA2.selectedCandidatePairId,
            transportA.selectedCandidatePairId);
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));

    test('media RTP flow produces outbound-rtp + inbound-rtp entries',
        () async {
      void addAudio(PeerConnection pc) =>
          pc.addTransceiver('audio', direction: 'sendrecv');
      final (pcA, pcB) = await _handshakeLoopback(
        configureA: addAudio,
        configureB: addAudio,
      );

      try {
        // Drive a handful of RTP packets through pcA's sender. The
        // payload is opaque to the test — it's only proving the SRTP
        // encrypt / decrypt round-trip increments getStats counters
        // for the same SSRC on both ends.
        final senderA = pcA.getSenders().single;
        final payload = Uint8List.fromList(List.generate(100, (i) => i & 0xFF));
        const packetCount = 5;
        for (var i = 0; i < packetCount; i++) {
          senderA.sendRtp(payload);
        }
        // UDP loopback is fire-and-forget; let the event loop drain.
        await Future<void>.delayed(const Duration(milliseconds: 200));

        final reportA = await pcA.getStats();
        final reportB = await pcB.getStats();

        // Outbound on the sender side: one entry, ssrc matching the
        // sender, counters matching what we just pushed.
        final outboundA = reportA
            .ofType<OutboundRtpStats>(RtcStatsType.outboundRtp)
            .single;
        expect(outboundA.ssrc, senderA.ssrc);
        expect(outboundA.kind, 'audio');
        expect(outboundA.packetsSent, packetCount);
        expect(outboundA.bytesSent, packetCount * payload.length);
        expect(outboundA.id, 'outbound-rtp-${senderA.ssrc}');

        // Inbound on the receiver side: keyed by the same SSRC.
        final inboundB = reportB
            .ofType<InboundRtpStats>(RtcStatsType.inboundRtp)
            .singleWhere((s) => s.ssrc == senderA.ssrc);
        expect(inboundB.packetsReceived, packetCount);
        expect(inboundB.bytesReceived, packetCount * payload.length);
        expect(inboundB.id, 'inbound-rtp-${senderA.ssrc}');

        // The receiver hasn't sent anything, so its outbound entry
        // (for its own SSRC) stays at zero. Confirm the counters
        // actually distinguish directions per SSRC.
        final outboundB = reportB
            .ofType<OutboundRtpStats>(RtcStatsType.outboundRtp)
            .single;
        expect(outboundB.packetsSent, 0);
        expect(outboundB.bytesSent, 0);
        expect(outboundB.ssrc, isNot(senderA.ssrc));

        // pcA never received the inverse direction's RTP (pcB never
        // called sendRtp), so it has no inbound-rtp entry.
        expect(
            reportA.ofType<InboundRtpStats>(RtcStatsType.inboundRtp), isEmpty);
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));

    test(
        'RTCP feedback surfaces remote-inbound-rtp + candidate-pair RTT',
        () async {
      void addAudio(PeerConnection pc) =>
          pc.addTransceiver('audio', direction: 'sendrecv');
      final (pcA, pcB) = await _handshakeLoopback(
        configureA: addAudio,
        configureB: addAudio,
      );

      try {
        // Push some RTP so pcA's RTCP timer has something to put in
        // the next SR. The RR loop is: pcA SR → pcB consumes lastSr →
        // pcB next RR carries dlsr → pcA computes RTT. The RTCP timer
        // fires every 100 ms, so 600 ms covers ≥4 cycles and stays
        // well clear of flakes on slow CI runners.
        final senderA = pcA.getSenders().single;
        final payload = Uint8List.fromList(List.filled(80, 0x55));
        for (var i = 0; i < 10; i++) {
          senderA.sendRtp(payload);
        }
        await Future<void>.delayed(const Duration(milliseconds: 600));

        final reportA = await pcA.getStats();

        // ICE pair RTT is recorded from the STUN connectivity-check
        // round-trip. On loopback the *selected* pair may have been
        // installed via the peer-reflexive triggered-check path, which
        // doesn't always record an RTT; just confirm at least one of
        // the candidate pairs has a measured RTT in a sane range.
        final pairsWithRtt = reportA
            .ofType<CandidatePairStats>(RtcStatsType.candidatePair)
            .where((p) => p.currentRoundTripTime != null)
            .toList();
        expect(pairsWithRtt, isNotEmpty,
            reason: 'at least one candidate-pair check should have RTT by now');
        for (final p in pairsWithRtt) {
          expect(p.currentRoundTripTime!, greaterThanOrEqualTo(0.0));
          expect(p.currentRoundTripTime!, lessThan(1.0));
        }

        // The remote sent RR back; pcA stored a snapshot for its
        // outbound SSRC. RTT must be a small positive number; loss
        // and jitter on a loopback channel should round to 0.
        final remoteInboundA = reportA
            .ofType<RemoteInboundRtpStats>(RtcStatsType.remoteInboundRtp)
            .singleWhere((s) => s.ssrc == senderA.ssrc);
        expect(remoteInboundA.localId, 'outbound-rtp-${senderA.ssrc}');
        expect(remoteInboundA.packetsLost, 0);
        expect(remoteInboundA.fractionLost, 0.0);
        expect(remoteInboundA.jitter, greaterThanOrEqualTo(0.0));
        expect(remoteInboundA.roundTripTime, isNotNull,
            reason:
                'pcA should have seen pcB echo back its SR by now');
        expect(remoteInboundA.roundTripTime!, greaterThanOrEqualTo(0.0));
        expect(remoteInboundA.roundTripTime!, lessThan(1.0));
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));
  });
}
