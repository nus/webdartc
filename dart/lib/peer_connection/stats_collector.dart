part of 'peer_connection.dart';

/// Assembles the W3C §8 `RTCStatsReport` snapshot for one [PeerConnection]
/// from the transport, ICE agent, RTCP session, and data channels.
final class StatsCollector {
  final PeerConnection _pc;

  StatsCollector(this._pc);

  /// Snapshot of stats across the PeerConnection's transport, ICE agent,
  /// and data channels. Returned counters are monotonic; callers compute
  /// deltas across snapshots themselves.
  RtcStatsReport collect() {
    final now = DateTime.now();
    final entries = <String, RtcStats>{};

    final (dcOpened, dcClosed) = _collectDataChannelStats(entries, now);
    final selectedPairId = _collectIceStats(entries, now);
    _collectRtpStats(entries, now);
    final (localCertId, remoteCertId) = _collectCertificateStats(entries, now);

    entries['transport'] = TransportStats(
      id: 'transport',
      timestamp: now,
      bytesSent: _pc._transport.bytesSent,
      bytesReceived: _pc._transport.bytesReceived,
      packetsSent: _pc._transport.packetsSent,
      packetsReceived: _pc._transport.packetsReceived,
      selectedCandidatePairId: selectedPairId,
      localCertificateId: localCertId,
      remoteCertificateId: remoteCertId,
    );

    entries['pc'] = PeerConnectionStats(
      id: 'pc',
      timestamp: now,
      dataChannelsOpened: dcOpened,
      dataChannelsClosed: dcClosed,
    );

    return RtcStatsReport(entries);
  }

  /// One [DataChannelStats] per channel; returns the (opened, closed)
  /// counts for the summary [PeerConnectionStats] entry.
  (int, int) _collectDataChannelStats(
      Map<String, RtcStats> entries, DateTime now) {
    var dcOpened = 0;
    var dcClosed = 0;
    for (final dc in _pc._dataChannels.values) {
      if (dc.readyState == DataChannelState.open) dcOpened++;
      if (dc.readyState == DataChannelState.closed) dcClosed++;
      final id = 'dc-${dc.id}';
      entries[id] = DataChannelStats(
        id: id,
        timestamp: now,
        label: dc.label,
        state: dc.readyState.name,
        messagesSent: dc.messagesSent,
        bytesSent: dc.bytesSent,
        messagesReceived: dc.messagesReceived,
        bytesReceived: dc.bytesReceived,
      );
    }
    return (dcOpened, dcClosed);
  }

  /// Candidate-pair + local/remote candidate entries; returns the id of
  /// the selected pair (for the transport entry), or null when none.
  String? _collectIceStats(Map<String, RtcStats> entries, DateTime now) {
    String? selectedPairId;
    for (final pair in _pc._ice.pairs) {
      final localId = pair.local.statsId(isLocal: true);
      final remoteId = pair.remote.statsId(isLocal: false);
      // ICE state machine de-dupes by candidate coords in `_addPair`,
      // so this structured id is collision-free: one entry per
      // (local-candidate, remote-candidate) coordinate.
      final pairId = 'pair-$localId-$remoteId';
      final isSelected = identical(_pc._ice.selectedPair, pair);
      if (isSelected) selectedPairId = pairId;
      entries[pairId] = CandidatePairStats(
        id: pairId,
        timestamp: now,
        localCandidateId: localId,
        remoteCandidateId: remoteId,
        state: pair.state.name,
        nominated: pair.nominated,
        currentRoundTripTime: pair.roundTripTimeMs == null
            ? null
            : pair.roundTripTimeMs! / 1000.0,
      );
    }
    for (final c in _pc._ice.localCandidates) {
      final id = c.statsId(isLocal: true);
      entries[id] = CandidateStats(
        id: id,
        type: RtcStatsType.localCandidate,
        timestamp: now,
        ip: c.ip.toCanonical(),
        port: c.port,
        protocol: c.transport,
        candidateType: c.type,
        priority: c.priority,
      );
    }
    for (final c in _pc._ice.remoteCandidates) {
      final id = c.statsId(isLocal: false);
      entries[id] = CandidateStats(
        id: id,
        type: RtcStatsType.remoteCandidate,
        timestamp: now,
        ip: c.ip.toCanonical(),
        port: c.port,
        protocol: c.transport,
        candidateType: c.type,
        priority: c.priority,
      );
    }
    return selectedPairId;
  }

  /// Media sources, codecs, and outbound/inbound (+ remote-*) RTP entries.
  void _collectRtpStats(Map<String, RtcStats> entries, DateTime now) {
    // Media sources + codecs are emitted first so the outbound /
    // inbound entries below can back-reference them by id.
    final mediaSourceIdByTrack = <String, String>{};
    for (final t in _pc._transceivers) {
      final track = t.sender?.track;
      if (track == null) continue;
      final id = 'media-source-${track.id}';
      if (mediaSourceIdByTrack.containsKey(track.id)) continue;
      mediaSourceIdByTrack[track.id] = id;
      entries[id] = MediaSourceStats(
        id: id,
        timestamp: now,
        trackIdentifier: track.id,
        kind: track.kind,
      );
    }
    final codecIdByPt = _emitCodecStats(entries, now);

    for (final t in _pc._transceivers) {
      final sender = t.sender;
      if (sender == null) continue;
      final outboundId = 'outbound-rtp-${sender.ssrc}';
      entries[outboundId] = OutboundRtpStats(
        id: outboundId,
        timestamp: now,
        ssrc: sender.ssrc,
        kind: sender.kind,
        packetsSent: sender.packetsSent,
        bytesSent: sender.bytesSent,
        // PT-only lookup — if the same PT shows up under multiple
        // m-lines the first one wins (see _emitCodecStats). A pair-
        // keyed (mid, pt) map would need RtpSender to expose its mid.
        codecId: codecIdByPt[sender.payloadType],
        mediaSourceId: mediaSourceIdByTrack[sender.track?.id],
      );
      // Emit a paired remote-inbound entry once the remote has actually
      // reported anything about this SSRC. `clockRate` converts the
      // RR's jitter field from RTP timestamp units to seconds.
      final remote = _pc._rtcp._remoteInboundStats[sender.ssrc];
      if (remote != null) {
        final remoteId = 'remote-inbound-rtp-${sender.ssrc}';
        entries[remoteId] = RemoteInboundRtpStats(
          id: remoteId,
          timestamp: now,
          ssrc: sender.ssrc,
          localId: outboundId,
          packetsLost: remote.packetsLost,
          fractionLost: remote.fractionLost,
          jitter: remote.jitterRtpUnits / sender.clockRate,
          roundTripTime: remote.roundTripTimeSeconds,
        );
      }
    }
    for (final s in _pc._rtcp._rtpRecvStats.values) {
      // Skip the placeholder entry created for the local sender's
      // SSRC in `setRemoteDescription` — it never gets a packet, so
      // emitting it would falsely suggest a paired inbound stream
      // that doesn't exist.
      if (s.packetsReceived == 0) continue;
      final id = 'inbound-rtp-${s.ssrc}';
      entries[id] = InboundRtpStats(
        id: id,
        timestamp: now,
        ssrc: s.ssrc,
        kind: s.kind,
        packetsReceived: s.packetsReceived,
        bytesReceived: s.bytesReceived,
        packetsLost: s.cumulativeLost,
        jitter: s.jitterSeconds,
        codecId: codecIdByPt[s.payloadType],
      );
      // Pair a remote-outbound entry from the remote's SR, when one has
      // arrived (the SR describes the sending side of this inbound SSRC).
      if (s.reportsReceived > 0) {
        final remoteId = 'remote-outbound-rtp-${s.ssrc}';
        entries[remoteId] = RemoteOutboundRtpStats(
          id: remoteId,
          timestamp: now,
          ssrc: s.ssrc,
          kind: s.kind,
          localId: id,
          packetsSent: s.srPacketCount,
          bytesSent: s.srOctetCount,
          remoteTimestamp: ntpToDateTime(s.srNtpHigh, s.srNtpLow),
          reportsReceived: s.reportsReceived,
        );
      }
    }
  }

  /// DTLS certificates. The local cert is sha-256 by impl
  /// (EcdsaCertificate); the remote algorithm comes verbatim from
  /// the SDP a=fingerprint line, so a peer using sha-384/sha-512
  /// gets reported as such instead of being mis-labelled. Returns the
  /// (local, remote) entry ids for the transport entry to reference.
  (String, String?) _collectCertificateStats(
      Map<String, RtcStats> entries, DateTime now) {
    const localCertId = 'certificate-local';
    entries[localCertId] = CertificateStats(
      id: localCertId,
      timestamp: now,
      fingerprint: _pc._localCert.sha256Fingerprint,
      fingerprintAlgorithm: 'sha-256',
    );
    String? remoteCertId;
    final remoteFp = _pc._negotiation._remoteFp;
    if (remoteFp != null) {
      remoteCertId = 'certificate-remote';
      entries[remoteCertId] = CertificateStats(
        id: remoteCertId,
        timestamp: now,
        fingerprint: remoteFp.hex,
        fingerprintAlgorithm: remoteFp.algorithm,
      );
    }
    return (localCertId, remoteCertId);
  }

  /// Whichever description is the agreed-upon answer — that's the
  /// narrowed codec list both sides committed to. Returns null while
  /// the offer/answer dance is still pending, in which case codec
  /// entries are skipped entirely.
  SdpSessionDescription? _agreedSdp() {
    final negotiation = _pc._negotiation;
    if (negotiation._localDescription?.type == SessionDescriptionType.answer) {
      return negotiation._localParsed;
    }
    if (negotiation._remoteDescription?.type == SessionDescriptionType.answer) {
      return negotiation._remoteParsed;
    }
    return null;
  }

  /// Emit one [CodecStats] per (m-line, payloadType) found in the
  /// agreed-upon SDP and return a `{payloadType: codecId}` map for
  /// outbound entries to back-reference. The same PT under multiple
  /// m-lines (rare but legal) collapses to the first one in the map —
  /// `getStats` reports the most-likely codec only.
  Map<int, String> _emitCodecStats(Map<String, RtcStats> entries, DateTime now) {
    final sdp = _agreedSdp();
    if (sdp == null) return const {};

    final out = <int, String>{};
    for (final m in sdp.media) {
      if (m.type != 'audio' && m.type != 'video') continue;
      final mid = m.mid;
      // BUNDLE makes `a=mid` mandatory; a missing one means malformed
      // SDP rather than something we should paper over with a `?`
      // placeholder that would collide across m-lines.
      if (mid == null) continue;

      // PT→fmtp lookup, hoisted out of the rtpmap loop below so the
      // fmtp scan happens once per m-line rather than once per codec.
      final fmtpByPt = m.fmtpByPayloadType();

      for (final rtpmap in m.getAll('rtpmap')) {
        // Format: "<PT> <codec>/<clock>[/<channels>]"
        final space = rtpmap.indexOf(' ');
        if (space < 0) continue;
        final pt = int.tryParse(rtpmap.substring(0, space));
        if (pt == null) continue;
        final parts = rtpmap.substring(space + 1).split('/');
        if (parts.isEmpty) continue;
        final codecName = parts[0];
        final clockRate = parts.length > 1 ? int.tryParse(parts[1]) ?? 0 : 0;
        final channels =
            parts.length > 2 ? int.tryParse(parts[2]) : null;
        final id = 'codec-$mid-$pt';
        entries[id] = CodecStats(
          id: id,
          timestamp: now,
          payloadType: pt,
          mimeType: '${m.type}/$codecName',
          clockRate: clockRate,
          channels: channels,
          sdpFmtpLine: fmtpByPt[pt],
        );
        out.putIfAbsent(pt, () => id);
      }
    }
    return out;
  }
}
