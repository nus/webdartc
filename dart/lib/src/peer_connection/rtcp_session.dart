part of 'peer_connection.dart';

/// RTCP send/receive engine for one [PeerConnection]: periodic compound
/// RR/SR + SDES (+ REMB, PLI/FIR, transport-cc feedback), inbound SR/RR
/// ingestion, and the per-SSRC reception/remote-inbound stat tables that
/// feed both the reports and `getStats()`.
///
/// Owns the 100 ms RTCP timer, which doubles as the receive-pipeline pump
/// (see [_startTimer]).
final class RtcpSession {
  final PeerConnection _pc;

  RtcpSession(this._pc);

  /// RTP reception stats per remote SSRC, for RTCP RR + getStats inboundRtp.
  final Map<int, _RtpRecvStats> _rtpRecvStats = {};

  /// Latest RTCP-RR snapshot per our outbound SSRC. Populated when the
  /// remote peer sends a Receiver Report whose report block names
  /// that SSRC; surfaced via `getStats()` as `RemoteInboundRtpStats`.
  final Map<int, _RemoteInboundStats> _remoteInboundStats = {};

  /// SSRCs needing PLI in the next periodic compound RTCP.
  final Set<int> _pendingPliSsrcs = {};

  // Transport-CC state
  int _twccExtId = 0; // extension ID from SDP (0 = not negotiated)
  final List<_TwccEntry> _twccRecvLog = [];
  int _twccFbCount = 0;

  /// Our SSRC for RTCP reports when no sender is active.
  final int _localRtcpSsrc = Csprng.randomUint32();

  Timer? _rtcpTimer;

  void _close() {
    _rtcpTimer?.cancel();
  }

  // ── Inbound ───────────────────────────────────────────────────────────────

  void _onRtcpReceived(Uint8List data) {
    final result = RtpParser.parseRtcp(data);
    if (result.isErr) return;
    for (final pkt in result.value) {
      if (PeerConnection._debug) {
        webdartcLog('[pc] RTCP received: ${pkt.runtimeType}');
      }
      if (pkt is RtcpSenderReport) {
        // Update stats with SR info and send RR back. The SR describes the
        // remote's own outbound stream (our inbound SSRC) — capture it for
        // `remote-outbound-rtp`.
        final stats =
            _rtpRecvStats.putIfAbsent(pkt.ssrc, () => _RtpRecvStats(pkt.ssrc));
        stats.lastSrReceivedAt = DateTime.now();
        stats.srPacketCount = pkt.packetCount;
        stats.srOctetCount = pkt.octetCount;
        stats.srNtpHigh = pkt.ntpTimestampHigh;
        stats.srNtpLow = pkt.ntpTimestampLow;
        stats.reportsReceived++;
        _ingestReportBlocks(pkt.reportBlocks);
        _sendRtcpRR();
      } else if (pkt is RtcpReceiverReport) {
        _ingestReportBlocks(pkt.reportBlocks);
      }
    }
  }

  /// RFC 3550 §6.4.1: RR/SR report blocks describe how the *remote*
  /// peer is receiving one of our outbound SSRCs. Store the latest
  /// snapshot per SSRC, plus a freshly-computed RTT when the remote
  /// has echoed a non-zero `lastSr`. Blocks naming an SSRC we don't
  /// own are dropped — without that gate a misbehaving peer can grow
  /// the map without bound by flooding RRs with random SSRCs.
  void _ingestReportBlocks(List<RtcpReportBlock> blocks) {
    if (blocks.isEmpty) return;
    final knownSsrcs = {
      for (final t in _pc._transceivers)
        if (t.sender != null) t.sender!.ssrc,
    };
    if (knownSsrcs.isEmpty) return;
    final nowCompact = currentCompactNtp(DateTime.now());
    for (final b in blocks) {
      if (!knownSsrcs.contains(b.ssrc)) continue;
      final s = _remoteInboundStats.putIfAbsent(b.ssrc, _RemoteInboundStats.new);
      s.packetsLost = sext24(b.cumulativeLost);
      s.fractionLost = b.fractionLost / rtcpFractionLostScale;
      s.jitterRtpUnits = b.jitter;
      final rtt = rttSeconds(
        nowCompactNtp: nowCompact,
        lastSr: b.lastSr,
        dlsrNtp: b.delaySinceLastSr,
      );
      if (rtt != null) s.roundTripTimeSeconds = rtt;
    }
  }

  /// Record a received RTP packet's transport-cc sequence number (from the
  /// negotiated header extension) for the next feedback packet.
  void _recordTwcc(RtpPacket rtp, int arrivalUs) {
    if (_twccExtId <= 0) return;
    if (rtp.headerExtension != null) {
      final elements = rtp.headerExtension!.parseElements();
      for (final ext in elements) {
        if (ext.id == _twccExtId && ext.data.length >= 2) {
          final twccSeq = readU16(ext.data, 0);
          _twccRecvLog.add(_TwccEntry(twccSeq, arrivalUs));
          if (PeerConnection._debug && _twccRecvLog.length <= 3) {
            webdartcLog(
                '[pc] twcc seq=$twccSeq (ext elements=${elements.length})');
          }
        }
      }
      if (elements.isEmpty && PeerConnection._debug) {
        webdartcLog(
            '[pc] headerExt present but 0 elements (profile=0x${rtp.headerExtension!.profile.toRadixString(16)}, dataLen=${rtp.headerExtension!.data.length})');
      }
    } else if (PeerConnection._debug && _pc._receivers.length <= 1) {
      webdartcLog(
          '[pc] no headerExtension on RTP pt=${rtp.payloadType} ext=${rtp.extension}');
    }
  }

  // ── Outbound ──────────────────────────────────────────────────────────────

  void _sendPli(int mediaSourceSsrc) {
    // Queue PLI to be sent on the next periodic compound RTCP. The compound's
    // sender SSRC is either an active video sender (preferred — Chrome
    // already knows it from a=ssrc) or `_localRtcpSsrc` when this side is
    // receive-only; the same `_localRtcpSsrc` carries the RR + SDES + REMB
    // in that compound and Chrome accepts those, so PLI rides along.
    _pendingPliSsrcs.add(mediaSourceSsrc);
    if (PeerConnection._debug) {
      webdartcLog('[pc] queued PLI for ssrc=$mediaSourceSsrc');
    }
  }

  void _startTimer() {
    _rtcpTimer?.cancel();
    // Send RTCP RR + transport-cc and pump receive pipelines every 100ms.
    // The receive pipelines deliberately share this timer rather than owning a
    // separate one — jitter-buffer playout granularity is therefore 100ms,
    // coarser than the 50ms default playout delay but adequate; revisit with a
    // dedicated faster pump if playout latency becomes a concern.
    _rtcpTimer = Timer.periodic(const Duration(milliseconds: 100), (_) {
      _sendRtcpRR();
      _tickReceivers();
    });
    Future<void>.delayed(const Duration(milliseconds: 50), _sendRtcpRR);
  }

  /// Pump each receiver's decode pipeline: release jitter-buffered packets,
  /// depacketize, decode, and retransmit PLI as needed. Uses the transport's
  /// monotonic clock so playout timing matches packet arrival timestamps.
  void _tickReceivers() {
    if (_pc._receivers.isEmpty) return;
    final nowUs = _pc._transport.nowUs;
    for (final r in _pc._receivers.values) {
      r._tick(nowUs);
    }
  }

  void _sendRtcpRR() {
    final srtp = _pc._srtp;
    if (srtp == null) return;

    // Only include RR blocks for SSRCs that have actually sent packets.
    final blocks = <RtcpReportBlock>[];
    for (final stats in _rtpRecvStats.values) {
      if (stats.packetsReceived == 0) continue;
      final dlsr = stats.lastSrReceivedAt != null
          ? ((DateTime.now().difference(stats.lastSrReceivedAt!).inMicroseconds *
                  65536) ~/
              1000000)
          : 0;
      blocks.add(RtcpReportBlock(
        ssrc: stats.ssrc,
        fractionLost: stats.takeFractionLost(),
        // RR cumulative-lost is a 24-bit two's-complement field.
        cumulativeLost: stats.cumulativeLost & 0xFFFFFF,
        extendedHighestSeq: stats.extendedHighestSeq,
        jitter: stats.jitterRtpUnits.round(),
        lastSr: stats.lastSrNtp,
        delaySinceLastSr: dlsr,
      ));
    }

    // Build compound RTCP: SR/RR + SDES(CNAME) [+ REMB] [+ Transport-CC]
    // RFC 3550 §6.1 requires compound packets with SR/RR + SDES as minimum.
    // Use SR if we are actively sending RTP, RR otherwise.
    final compound = <int>[];

    // Determine SSRC for this compound packet — must be consistent across
    // all sub-packets (SR/RR, SDES, etc.) per RFC 3550 §6.1.
    final activeSenders = _pc._transceivers
        .where((t) => t.sender != null && t.sender!._packetsSent > 0)
        .map((t) => t.sender!)
        .toList();

    // Send SR for an active sender, or RR if no sender is active.
    // When PLI is pending, prefer the video sender so Chrome associates
    // the compound with the video m= line.
    final int compoundSsrc;
    if (activeSenders.isNotEmpty) {
      final sender = (_pendingPliSsrcs.isNotEmpty
          ? activeSenders.where((s) => s.kind == 'video').firstOrNull
          : null) ?? activeSenders.first;
      compoundSsrc = sender.ssrc;
      final ntp = ntpTimestampOf(DateTime.now());
      compound.addAll(RtcpSenderReport(
        ssrc: compoundSsrc,
        ntpTimestampHigh: ntp.high,
        ntpTimestampLow: ntp.low,
        rtpTimestamp: sender._lastRtpTimestamp,
        packetCount: sender._packetsSent,
        octetCount: sender._octetsSent,
        reportBlocks: blocks,
      ).build());
    } else {
      compoundSsrc = _localRtcpSsrc;
      compound.addAll(RtcpReceiverReport(ssrc: compoundSsrc, reportBlocks: blocks).build());
    }
    compound.addAll(RtcpSdes(chunks: [
      RtcpSdesChunk(ssrc: compoundSsrc, items: {1: 'webdartc'}),
    ]).build());

    // REMB for video bandwidth signaling
    if (_pc._transceivers.any((t) => t.kind == 'video')) {
      final remoteSsrcs = _rtpRecvStats.keys.where((ssrc) {
        final s = _rtpRecvStats[ssrc];
        return s != null && s.packetsReceived > 0;
      }).toList();
      if (remoteSsrcs.isNotEmpty) {
        compound.addAll(RtcpRemb(
          senderSsrc: compoundSsrc,
          bitrate: 10000000, // 10 Mbps
          mediaSsrcs: remoteSsrcs,
        ).build());
      }
    }

    // Pending keyframe requests (PLI + FIR, RFC 4585/5104). Piggybacks
    // on the same compound that just carried RR + SDES (+ REMB) — all use
    // `compoundSsrc`, which is the active video sender's SSRC when one
    // exists and `_localRtcpSsrc` for receive-only sessions. Chrome
    // accepts both. Keep retrying until cleared externally.
    if (_pendingPliSsrcs.isNotEmpty) {
      for (final mediaSsrc in _pendingPliSsrcs) {
        // PLI (RFC 4585 §6.3.1)
        compound.addAll(RtcpPli(senderSsrc: compoundSsrc, mediaSourceSsrc: mediaSsrc).build());
        // FIR (RFC 5104 §4.3.1) — some implementations respond to FIR but not PLI
        final fir = Uint8List(20);
        fir[0] = 0x80 | 4; // V=2, FMT=4
        fir[1] = 206; // PT=PSFB
        writeU16(fir, 2, 4); // length=4
        writeU32(fir, 4, compoundSsrc); // sender SSRC
        writeU32(fir, 8, 0); // media source (unused in FIR)
        writeU32(fir, 12, mediaSsrc); // FCI: target SSRC
        fir[16] = 1; // Seq nr
        compound.addAll(fir);
      }
      if (PeerConnection._debug) {
        webdartcLog(
            '[pc] PLI+FIR for ssrcs=$_pendingPliSsrcs (sender=$compoundSsrc)');
      }
    }

    // Transport-cc feedback — use a consistent known SSRC so Chrome's
    // transport-cc processor always matches it to our session.
    final videoSender = _pc._transceivers
        .where((t) => t.kind == 'video' && t.sender != null)
        .map((t) => t.sender!)
        .firstOrNull;
    if (videoSender != null) {
      // mediaSsrc: Chrome expects the SSRC of the media stream being fed
      // back, despite the spec saying 0. Use first known remote video SSRC.
      final remoteVideoSsrc = _pc._receivers.entries
          .where((e) => e.value.kind == 'video')
          .map((e) => e.key)
          .firstOrNull ?? _rtpRecvStats.keys.firstOrNull ?? 0;
      final ccBytes = _buildTransportCcFeedback(videoSender.ssrc, remoteVideoSsrc);
      if (ccBytes != null) compound.addAll(ccBytes);
    }

    _pc._transport.sendRtp(srtp.encryptRtcp(Uint8List.fromList(compound)));
    if (PeerConnection._debug) {
      webdartcLog(
          '[pc] sent compound RTCP (${compound.length}b): RR(${blocks.length})');
    }
  }

  Uint8List? _buildTransportCcFeedback(int senderSsrc, int mediaSsrc) {
    if (_twccRecvLog.isEmpty) return null;

    // Consume all pending entries
    final entries = List<_TwccEntry>.from(_twccRecvLog);
    _twccRecvLog.clear();

    // Build seq → arrival map, handling duplicates by keeping earliest.
    final arrivalMap = <int, int>{};
    for (final e in entries) {
      arrivalMap.putIfAbsent(e.seq, () => e.arrivalUs);
    }

    // Determine full sequence range.
    final seqs = arrivalMap.keys.toList()..sort();
    final baseSeq = seqs.first;
    final maxSeq = seqs.last;
    final statusCount = maxSeq - baseSeq + 1;
    final baseTimeUs = arrivalMap[baseSeq]!;

    // Reference time is quantized to 64ms. The first delta captures the
    // sub-64ms remainder so cross-feedback timing stays accurate to 250µs.
    final referenceTimeMs = baseTimeUs ~/ 1000;
    final refTimeQuantizedUs = (referenceTimeMs ~/ 64) * 64 * 1000;

    // Build deltas for the full range [baseSeq, maxSeq].
    // null = not received, non-null = inter-arrival delta in µs.
    final deltas = <int?>[];
    var prevUs = refTimeQuantizedUs; // start from quantized reference, NOT baseTimeUs
    for (var seq = baseSeq; seq <= maxSeq; seq++) {
      final arrival = arrivalMap[seq];
      if (arrival == null) {
        deltas.add(null); // not received
      } else {
        deltas.add(arrival - prevUs);
        prevUs = arrival;
      }
    }

    final fb = RtcpTransportCc(
      senderSsrc: senderSsrc,
      mediaSsrc: mediaSsrc,
      baseSeq: baseSeq,
      referenceTimeMs: referenceTimeMs,
      fbPktCount: _twccFbCount & 0xFF,
      recvDeltasUs: deltas,
    );
    _twccFbCount++;

    final rawFb = fb.build();
    if (PeerConnection._debug) {
      webdartcLog(
          '[pc] transport-cc fb: base=$baseSeq count=$statusCount recv=${seqs.length}');
    }
    return rawFb;
  }
}

final class _RtpRecvStats {
  final int ssrc;
  String kind = '';
  int payloadType = -1;
  int bytesReceived = 0;

  // RFC 3550 loss + interarrival jitter. Bound on the first packet, once
  // the PT (and hence clock rate) is known via [bind] — entries
  // pre-populated from SDP SSRC attributes or an SR start unbound.
  RtpReceptionTracker? _tracker;

  // Latest RTCP SR detail for this (remote) SSRC — the remote's view of
  // its own outbound stream, surfaced as `remote-outbound-rtp`.
  DateTime? lastSrReceivedAt;
  int srPacketCount = 0;
  int srOctetCount = 0;
  int srNtpHigh = 0;
  int srNtpLow = 0;
  int reportsReceived = 0;

  _RtpRecvStats(this.ssrc);

  bool get isBound => _tracker != null;
  int get packetsReceived => _tracker?.packetsReceived ?? 0;
  int get extendedHighestSeq => _tracker?.extendedHighestSeq ?? 0;
  int get cumulativeLost => _tracker?.cumulativeLost ?? 0;
  double get jitterRtpUnits => _tracker?.jitter ?? 0;
  double get jitterSeconds => _tracker?.jitterSeconds ?? 0;
  int takeFractionLost() => _tracker?.takeFractionLost() ?? 0;

  /// Compact NTP of the last SR, echoed back as our RR's `lastSr`
  /// (0 until an SR has arrived).
  int get lastSrNtp =>
      reportsReceived > 0 ? compactNtpOf(srNtpHigh, srNtpLow) : 0;

  /// Bind the loss/jitter tracker once the stream's codec is known.
  void bind({
    required String kind,
    required int payloadType,
    required int clockRate,
  }) {
    this.kind = kind;
    this.payloadType = payloadType;
    _tracker = RtpReceptionTracker(clockRate);
  }

  void update({
    required int seq,
    required int rtpTimestamp,
    required int arrivalUs,
    required int payloadBytes,
  }) {
    _tracker!.onPacket(seq: seq, rtpTimestamp: rtpTimestamp, arrivalUs: arrivalUs);
    bytesReceived += payloadBytes;
  }
}

/// Latest snapshot from a Receiver Report block the remote sent about
/// one of our outbound SSRCs. `roundTripTime` is null until we've
/// received an RR that echoes a non-zero `lastSr` (which only happens
/// after the peer has both received an SR from us and replied at
/// least once).
final class _RemoteInboundStats {
  int packetsLost = 0;
  double fractionLost = 0;
  int jitterRtpUnits = 0;
  double? roundTripTimeSeconds;
}

final class _TwccEntry {
  final int seq;
  final int arrivalUs;
  const _TwccEntry(this.seq, this.arrivalUs);
}
