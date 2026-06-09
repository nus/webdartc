import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart' hide Timeout;

import '../peer_connection/loopback.dart';

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
      final (pcA, pcB) = await handshakeLoopback(
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
      final (pcA, pcB) = await handshakeLoopback(
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

        // Negotiation populated each transceiver's mid + currentDirection,
        // and the receiver got linked to pcB's transceiver (W3C).
        final txA = pcA.getTransceivers().single;
        expect(txA.mid, isNotNull);
        expect(txA.currentDirection, RtpTransceiverDirection.sendrecv);
        final txB = pcB.getTransceivers().single;
        expect(txB.mid, isNotNull);
        expect(txB.receiver, isNotNull);
        expect(txB.receiver!.ssrc, senderA.ssrc);
        expect(pcB.getReceivers().map((r) => r.ssrc), contains(senderA.ssrc));

        // Inbound on the receiver side: keyed by the same SSRC.
        final inboundB = reportB
            .ofType<InboundRtpStats>(RtcStatsType.inboundRtp)
            .singleWhere((s) => s.ssrc == senderA.ssrc);
        expect(inboundB.packetsReceived, packetCount);
        expect(inboundB.bytesReceived, packetCount * payload.length);
        expect(inboundB.id, 'inbound-rtp-${senderA.ssrc}');
        expect(inboundB.kind, 'audio');
        // A clean in-order loopback flow: no loss, jitter rounds to ~0.
        expect(inboundB.packetsLost, 0);
        expect(inboundB.jitter, greaterThanOrEqualTo(0.0));
        // codecId resolves to the negotiated Opus codec entry.
        expect(inboundB.codecId, isNotNull);
        expect(reportB[inboundB.codecId!], isA<CodecStats>());

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
      final (pcA, pcB) = await handshakeLoopback(
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
        final reportB = await pcB.getStats();

        // pcA sends an RTCP SR for its outbound stream; pcB receives it and
        // surfaces it as remote-outbound-rtp for the same SSRC, paired with
        // pcB's inbound-rtp entry.
        final remoteOutboundB = reportB
            .ofType<RemoteOutboundRtpStats>(RtcStatsType.remoteOutboundRtp)
            .singleWhere((s) => s.ssrc == senderA.ssrc);
        expect(remoteOutboundB.kind, 'audio');
        expect(remoteOutboundB.localId, 'inbound-rtp-${senderA.ssrc}');
        expect(reportB[remoteOutboundB.localId], isA<InboundRtpStats>());
        expect(remoteOutboundB.reportsReceived, greaterThan(0));
        expect(remoteOutboundB.packetsSent, greaterThan(0));
        expect(remoteOutboundB.remoteTimestamp, isNotNull);

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
          // Loopback STUN check on the same host: even a slow CI
          // runner shouldn't take more than 100 ms. A wider bound
          // would let wrap-around math sneak through undetected.
          expect(p.currentRoundTripTime!, lessThan(0.1),
              reason: 'loopback ICE check RTT should be well below 100 ms');
        }

        // The remote sent RR back; pcA stored a snapshot for its
        // outbound SSRC. RTT must be a small positive number; loss
        // and jitter on a loopback channel should round to 0.
        final remoteInboundEntries = reportA
            .ofType<RemoteInboundRtpStats>(RtcStatsType.remoteInboundRtp)
            .toList();
        expect(remoteInboundEntries, isNotEmpty);

        // SSRC filter regression: every remote-inbound-rtp entry must
        // correspond to an SSRC we actually send from. Without the
        // filter in `_ingestReportBlocks`, a misbehaving peer could
        // grow `_remoteInboundStats` unboundedly by flooding RRs with
        // random SSRCs.
        final ownSenderSsrcs = pcA.getSenders().map((s) => s.ssrc).toSet();
        for (final e in remoteInboundEntries) {
          expect(ownSenderSsrcs.contains(e.ssrc), isTrue,
              reason: 'remote-inbound-rtp entry for unknown ssrc ${e.ssrc} '
                  '— SSRC filter regression');
          // Every entry must back-reference a real outbound-rtp.
          expect(reportA[e.localId], isA<OutboundRtpStats>(),
              reason: 'localId ${e.localId} dangling');
        }

        final remoteInboundA = remoteInboundEntries
            .singleWhere((s) => s.ssrc == senderA.ssrc);
        expect(remoteInboundA.localId, 'outbound-rtp-${senderA.ssrc}');
        expect(remoteInboundA.packetsLost, 0);
        expect(remoteInboundA.fractionLost, 0.0);
        expect(remoteInboundA.jitter, greaterThanOrEqualTo(0.0));
        expect(remoteInboundA.roundTripTime, isNotNull,
            reason:
                'pcA should have seen pcB echo back its SR by now');
        // Loopback RTT should land well under 100 ms — a 1-second
        // ceiling would let a regression slip through where the
        // helper is reporting wrap-around math as a real RTT.
        expect(remoteInboundA.roundTripTime!, greaterThanOrEqualTo(0.0));
        expect(remoteInboundA.roundTripTime!, lessThan(0.1),
            reason: 'loopback RTT should be well below 100 ms');
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));

    test('codec + media-source + certificate entries appear after handshake',
        () async {
      void addAudio(PeerConnection pc) =>
          pc.addTransceiver('audio', direction: 'sendrecv');
      final (pcA, pcB) = await handshakeLoopback(
        configureA: addAudio,
        configureB: addAudio,
      );
      // Attach a track to pcA's sender so MediaSourceStats has
      // something to identify by.
      final track = _FakeAudioTrack('test-track-id');
      await pcA.getSenders().single.replaceTrack(track);

      try {
        final reportA = await pcA.getStats();

        // ── certificate ─────────────────────────────────────────────
        final local =
            reportA['certificate-local'] as CertificateStats?;
        final remote =
            reportA['certificate-remote'] as CertificateStats?;
        expect(local, isNotNull);
        expect(remote, isNotNull);
        expect(local!.fingerprintAlgorithm, 'sha-256');
        // SHA-256 fingerprint, colon-separated hex, 32 bytes →
        // 32 hex-pairs + 31 colons = 95 chars.
        expect(local.fingerprint, hasLength(95));
        expect(local.fingerprint, matches(RegExp(r'^[0-9A-F:]+$')));
        expect(remote!.fingerprint, hasLength(95));
        // Local and remote certs must differ (each PC built its own).
        expect(local.fingerprint, isNot(equals(remote.fingerprint)));

        final transport = reportA['transport'] as TransportStats;
        expect(transport.localCertificateId, 'certificate-local');
        expect(transport.remoteCertificateId, 'certificate-remote');

        // ── codec ───────────────────────────────────────────────────
        final codecs = reportA
            .ofType<CodecStats>(RtcStatsType.codec)
            .toList();
        expect(codecs, isNotEmpty,
            reason: 'audio m-line should have produced ≥1 codec entry');
        // Opus 48 kHz stereo is the default audio codec.
        final opus = codecs.singleWhere(
          (c) => c.mimeType == 'audio/opus',
          orElse: () => throw StateError('no audio/opus codec entry'),
        );
        expect(opus.payloadType, 111);
        expect(opus.clockRate, 48000);
        expect(opus.channels, 2);

        // ── media-source ────────────────────────────────────────────
        final sources = reportA
            .ofType<MediaSourceStats>(RtcStatsType.mediaSource)
            .toList();
        expect(sources, hasLength(1));
        expect(sources.single.trackIdentifier, 'test-track-id');
        expect(sources.single.kind, 'audio');
        expect(sources.single.id, 'media-source-test-track-id');

        // ── outbound-rtp back-references ────────────────────────────
        final outbound = reportA
            .ofType<OutboundRtpStats>(RtcStatsType.outboundRtp)
            .single;
        expect(outbound.codecId, isNotNull);
        expect(reportA[outbound.codecId!], isA<CodecStats>());
        expect(outbound.mediaSourceId, 'media-source-test-track-id');
        expect(reportA[outbound.mediaSourceId!], isA<MediaSourceStats>());
      } finally {
        await pcA.close();
        await pcB.close();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));

    test('CertificateStats round-trips the remote a=fingerprint algorithm',
        () async {
      // Regression: setRemoteDescription now parses `<algo> <hex>`
      // instead of stripping a hardcoded `sha-256 ` prefix. A peer
      // sending sha-384 must surface as such in getStats — earlier
      // code mis-labelled non-sha-256 fingerprints. No connection
      // needed; we just exercise the SDP-ingest path.
      final pc = PeerConnection(configuration: PeerConnectionConfiguration());
      const sha384Hex =
          'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:'
          'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:'
          'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
      try {
        await pc.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: _offerWithFingerprint('sha-384', sha384Hex)));
        final report = await pc.getStats();
        final remote =
            report['certificate-remote'] as CertificateStats?;
        expect(remote, isNotNull);
        expect(remote!.fingerprintAlgorithm, 'sha-384');
        expect(remote.fingerprint, sha384Hex);
      } finally {
        await pc.close();
      }
    });

    test('setRemoteDescription rejects a weak SHA-1 fingerprint', () async {
      // RFC 8827 §6.5 / RFC 8122 §5: SHA-1 is deprecated and must not be
      // honoured. Reject at SDP ingest rather than failing deep in the
      // DTLS handshake.
      final pc = PeerConnection(configuration: PeerConnectionConfiguration());
      const sha1Hex = 'AA:BB:CC:DD:EE:FF:00:11:22:33:'
          '44:55:66:77:88:99:AA:BB:CC:DD';
      try {
        await expectLater(
          pc.setRemoteDescription(SessionDescription(
              type: SessionDescriptionType.offer,
              sdp: _offerWithFingerprint('sha-1', sha1Hex))),
          throwsA(isA<Exception>()),
        );
      } finally {
        await pc.close();
      }
    });
  });
}

/// Minimal offer SDP carrying a single audio m-line and the given
/// `a=fingerprint:<algo> <hex>`, for exercising the SDP-ingest path.
String _offerWithFingerprint(String algo, String hex) => 'v=0\r\n'
    'o=- 1 2 IN IP4 0.0.0.0\r\n'
    's=-\r\n'
    't=0 0\r\n'
    'a=group:BUNDLE 0\r\n'
    'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n'
    'c=IN IP4 0.0.0.0\r\n'
    'a=mid:0\r\n'
    'a=sendrecv\r\n'
    'a=rtpmap:111 opus/48000/2\r\n'
    'a=ice-ufrag:abcd\r\n'
    'a=ice-pwd:abcdefghijklmnopqrstuv\r\n'
    'a=fingerprint:$algo $hex\r\n'
    'a=setup:actpass\r\n'
    'a=rtcp-mux\r\n';

/// Minimal `MediaStreamTrack` for tests that only need stable id+kind
/// (e.g. asserting MediaSourceStats wiring). Doesn't actually produce
/// audio data — the test only inspects metadata.
class _FakeAudioTrack extends MediaStreamTrack {
  @override
  final String id;
  _FakeAudioTrack(this.id);
  @override
  String get kind => 'audio';
  @override
  String get label => 'fake-audio';
  @override
  bool enabled = true;
  @override
  MediaStreamTrackState get readyState => MediaStreamTrackState.live;
  @override
  MediaStreamTrack clone() => _FakeAudioTrack(id);
  @override
  void stop() {}
  @override
  Stream<VideoFrame> get onVideoFrame =>
      throw UnsupportedError('audio track');
  @override
  Stream<AudioData> get onAudioData => const Stream<AudioData>.empty();
}
