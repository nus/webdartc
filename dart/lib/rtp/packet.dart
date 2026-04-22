import 'dart:typed_data';

/// RTP packet (RFC 3550 §5.1).
final class RtpPacket {
  final int version;   // always 2
  final bool padding;
  final bool extension;
  final List<int> csrcs;
  final bool marker;
  final int payloadType;
  final int sequenceNumber;
  final int timestamp;
  final int ssrc;
  final RtpExtension? headerExtension;
  final Uint8List payload;

  const RtpPacket({
    this.version = 2,
    this.padding = false,
    this.extension = false,
    this.csrcs = const [],
    this.marker = false,
    required this.payloadType,
    required this.sequenceNumber,
    required this.timestamp,
    required this.ssrc,
    this.headerExtension,
    required this.payload,
  });

  /// Serialize to wire format.
  Uint8List build() {
    final extBytes = headerExtension?.encode();
    final totalLen = 12 +
        csrcs.length * 4 +
        (extBytes?.length ?? 0) +
        payload.length;
    final out = Uint8List(totalLen);

    out[0] = (2 << 6) |
        (padding ? 0x20 : 0) |
        (extBytes != null ? 0x10 : 0) |
        (csrcs.length & 0x0F);
    out[1] = (marker ? 0x80 : 0) | (payloadType & 0x7F);
    out[2] = (sequenceNumber >> 8) & 0xFF;
    out[3] = sequenceNumber & 0xFF;
    out[4] = (timestamp >> 24) & 0xFF;
    out[5] = (timestamp >> 16) & 0xFF;
    out[6] = (timestamp >>  8) & 0xFF;
    out[7] = timestamp & 0xFF;
    out[8]  = (ssrc >> 24) & 0xFF;
    out[9]  = (ssrc >> 16) & 0xFF;
    out[10] = (ssrc >>  8) & 0xFF;
    out[11] = ssrc & 0xFF;

    var offset = 12;
    for (final csrc in csrcs) {
      out[offset++] = (csrc >> 24) & 0xFF;
      out[offset++] = (csrc >> 16) & 0xFF;
      out[offset++] = (csrc >>  8) & 0xFF;
      out[offset++] = csrc & 0xFF;
    }
    if (extBytes != null) {
      out.setRange(offset, offset + extBytes.length, extBytes);
      offset += extBytes.length;
    }
    out.setRange(offset, out.length, payload);
    return out;
  }
}

/// RTP header extension (RFC 5285 one-byte or two-byte form).
final class RtpExtension {
  final int profile; // e.g. 0xBEDE for one-byte, 0x100N for two-byte
  final Uint8List data;

  const RtpExtension({required this.profile, required this.data});

  /// Parse individual extension elements from the raw data.
  List<RtpExtensionElement> parseElements() {
    if (profile == 0xBEDE) return _parseOneByte();
    if ((profile & 0xFFF0) == 0x1000) return _parseTwoByte();
    return const [];
  }

  // RFC 5285 §4.2 — one-byte header: 0xBEDE
  List<RtpExtensionElement> _parseOneByte() {
    final elements = <RtpExtensionElement>[];
    var off = 0;
    while (off < data.length) {
      final byte = data[off];
      if (byte == 0) { off++; continue; } // padding
      final id = (byte >> 4) & 0x0F;
      if (id == 15) break; // terminator
      final len = (byte & 0x0F) + 1;
      off++;
      if (off + len > data.length) break;
      elements.add(RtpExtensionElement(id: id, data: data.sublist(off, off + len)));
      off += len;
    }
    return elements;
  }

  // RFC 5285 §4.3 — two-byte header: 0x100N
  List<RtpExtensionElement> _parseTwoByte() {
    final elements = <RtpExtensionElement>[];
    var off = 0;
    while (off + 1 < data.length) {
      final id = data[off];
      if (id == 0) { off++; continue; } // padding
      final len = data[off + 1];
      off += 2;
      if (off + len > data.length) break;
      elements.add(RtpExtensionElement(id: id, data: data.sublist(off, off + len)));
      off += len;
    }
    return elements;
  }

  Uint8List encode() {
    final padded = (data.length + 3) & ~3;
    final out = Uint8List(4 + padded);
    out[0] = (profile >> 8) & 0xFF;
    out[1] = profile & 0xFF;
    final words = padded ~/ 4;
    out[2] = (words >> 8) & 0xFF;
    out[3] = words & 0xFF;
    out.setRange(4, 4 + data.length, data);
    return out;
  }
}

/// Individual RTP header extension element.
final class RtpExtensionElement {
  final int id;
  final Uint8List data;
  const RtpExtensionElement({required this.id, required this.data});
}

// ── RTCP packets ─────────────────────────────────────────────────────────────

sealed class RtcpPacket {}

/// RTCP Sender Report (SR) — PT=200.
final class RtcpSenderReport extends RtcpPacket {
  final int ssrc;
  final int ntpTimestampHigh;
  final int ntpTimestampLow;
  final int rtpTimestamp;
  final int packetCount;
  final int octetCount;
  final List<RtcpReportBlock> reportBlocks;

  RtcpSenderReport({
    required this.ssrc,
    required this.ntpTimestampHigh,
    required this.ntpTimestampLow,
    required this.rtpTimestamp,
    required this.packetCount,
    required this.octetCount,
    this.reportBlocks = const [],
  });

  /// Serialize to wire format (RFC 3550 §6.4.1).
  Uint8List build() {
    final len = 28 + reportBlocks.length * 24;
    final out = Uint8List(len);
    out[0] = 0x80 | (reportBlocks.length & 0x1F); // V=2, RC
    out[1] = 200; // PT=SR
    final wordLen = (len ~/ 4) - 1;
    out[2] = (wordLen >> 8) & 0xFF;
    out[3] = wordLen & 0xFF;
    _writeU32(out, 4, ssrc);
    _writeU32(out, 8, ntpTimestampHigh);
    _writeU32(out, 12, ntpTimestampLow);
    _writeU32(out, 16, rtpTimestamp);
    _writeU32(out, 20, packetCount);
    _writeU32(out, 24, octetCount);
    var off = 28;
    for (final b in reportBlocks) {
      _writeU32(out, off, b.ssrc); off += 4;
      out[off] = b.fractionLost & 0xFF;
      out[off + 1] = (b.cumulativeLost >> 16) & 0xFF;
      out[off + 2] = (b.cumulativeLost >> 8) & 0xFF;
      out[off + 3] = b.cumulativeLost & 0xFF;
      off += 4;
      _writeU32(out, off, b.extendedHighestSeq); off += 4;
      _writeU32(out, off, b.jitter); off += 4;
      _writeU32(out, off, b.lastSr); off += 4;
      _writeU32(out, off, b.delaySinceLastSr); off += 4;
    }
    return out;
  }
}

/// RTCP Receiver Report (RR) — PT=201.
final class RtcpReceiverReport extends RtcpPacket {
  final int ssrc;
  final List<RtcpReportBlock> reportBlocks;
  RtcpReceiverReport({required this.ssrc, this.reportBlocks = const []});

  /// Serialize to wire format (RFC 3550 §6.4.2).
  Uint8List build() {
    final len = 8 + reportBlocks.length * 24;
    final out = Uint8List(len);
    out[0] = 0x80 | (reportBlocks.length & 0x1F); // V=2, RC
    out[1] = 201; // PT=RR
    final wordLen = (len ~/ 4) - 1;
    out[2] = (wordLen >> 8) & 0xFF;
    out[3] = wordLen & 0xFF;
    _writeU32(out, 4, ssrc);
    var off = 8;
    for (final rb in reportBlocks) {
      _writeU32(out, off, rb.ssrc); off += 4;
      out[off++] = rb.fractionLost & 0xFF;
      out[off++] = (rb.cumulativeLost >> 16) & 0xFF;
      out[off++] = (rb.cumulativeLost >>  8) & 0xFF;
      out[off++] = rb.cumulativeLost & 0xFF;
      _writeU32(out, off, rb.extendedHighestSeq); off += 4;
      _writeU32(out, off, rb.jitter); off += 4;
      _writeU32(out, off, rb.lastSr); off += 4;
      _writeU32(out, off, rb.delaySinceLastSr); off += 4;
    }
    return out;
  }
}

/// RTCP SDES — PT=202.
final class RtcpSdes extends RtcpPacket {
  final List<RtcpSdesChunk> chunks;
  RtcpSdes({required this.chunks});

  /// Serialize to wire format (RFC 3550 §6.5).
  Uint8List build() {
    final body = <int>[];
    for (final chunk in chunks) {
      // SSRC (4 bytes)
      body.addAll([
        (chunk.ssrc >> 24) & 0xFF, (chunk.ssrc >> 16) & 0xFF,
        (chunk.ssrc >> 8) & 0xFF, chunk.ssrc & 0xFF,
      ]);
      // SDES items: type(1) + length(1) + value
      for (final entry in chunk.items.entries) {
        final val = entry.value.codeUnits;
        body.add(entry.key);
        body.add(val.length);
        body.addAll(val);
      }
      body.add(0); // end marker
      // Pad chunk to 4-byte boundary
      while (body.length % 4 != 0) { body.add(0); }
    }
    final len = 4 + body.length;
    final out = Uint8List(len);
    out[0] = 0x80 | (chunks.length & 0x1F); // V=2, SC
    out[1] = 202; // PT=SDES
    final wordLen = (len ~/ 4) - 1;
    out[2] = (wordLen >> 8) & 0xFF;
    out[3] = wordLen & 0xFF;
    out.setRange(4, len, body);
    return out;
  }
}

/// RTCP BYE — PT=203.
final class RtcpBye extends RtcpPacket {
  final List<int> ssrcs;
  RtcpBye({required this.ssrcs});
}

/// RTCP NACK (RFC 4585) — PT=205, FMT=1.
final class RtcpNack extends RtcpPacket {
  final int mediaSourceSsrc;
  final int senderSsrc;
  final List<RtcpNackEntry> nacks;
  RtcpNack({
    required this.mediaSourceSsrc,
    required this.senderSsrc,
    required this.nacks,
  });
}

/// RTCP PLI (RFC 4585) — PT=206, FMT=1.
final class RtcpPli extends RtcpPacket {
  final int senderSsrc;
  final int mediaSourceSsrc;
  RtcpPli({required this.senderSsrc, required this.mediaSourceSsrc});

  /// Serialize to wire format (RFC 4585 §6.3.1).
  Uint8List build() {
    final out = Uint8List(12);
    out[0] = 0x80 | 1; // V=2, FMT=1
    out[1] = 206; // PT=PSFB
    out[2] = 0; out[3] = 2; // length=2 (words)
    _writeU32(out, 4, senderSsrc);
    _writeU32(out, 8, mediaSourceSsrc);
    return out;
  }
}

/// RTCP REMB (Receiver Estimated Maximum Bitrate) — draft-alvestrand-rmcat-remb.
final class RtcpRemb extends RtcpPacket {
  final int senderSsrc;
  final int bitrate; // bps
  final List<int> mediaSsrcs;
  RtcpRemb({required this.senderSsrc, required this.bitrate, required this.mediaSsrcs});

  Uint8List build() {
    final numSsrcs = mediaSsrcs.length;
    final len = 20 + numSsrcs * 4; // header(4)+sender(4)+media(4)+REMB(4)+bw(4)+SSRCs
    final out = Uint8List(len);
    out[0] = 0x80 | 15; // V=2, FMT=15 (AFB)
    out[1] = 206; // PT=PSFB
    final wordLen = (len ~/ 4) - 1;
    out[2] = (wordLen >> 8) & 0xFF;
    out[3] = wordLen & 0xFF;
    _writeU32(out, 4, senderSsrc);
    _writeU32(out, 8, 0); // media SSRC = 0 for REMB
    // "REMB" magic
    out[12] = 0x52; out[13] = 0x45; out[14] = 0x4D; out[15] = 0x42;
    // num SSRCs + mantissa/exponent
    // Encode bitrate as mantissa * 2^exp
    var mantissa = bitrate;
    var exp = 0;
    while (mantissa > 0x3FFFF) { mantissa >>= 1; exp++; }
    out[16] = numSsrcs;
    out[17] = ((exp & 0x3F) << 2) | ((mantissa >> 16) & 0x03);
    out[18] = (mantissa >> 8) & 0xFF;
    out[19] = mantissa & 0xFF;
    var off = 20;
    for (final ssrc in mediaSsrcs) {
      _writeU32(out, off, ssrc);
      off += 4;
    }
    return out;
  }
}

/// RTCP Transport-CC feedback (draft-holmer-rmcat-transport-wide-cc-extensions).
/// PT=205 (RTPFB), FMT=15.
///
/// [recvDeltasUs] covers the full sequence range [baseSeq, baseSeq+length-1].
/// null entries mean "not received". Non-null entries are inter-arrival deltas
/// in microseconds (first entry is relative to referenceTime, subsequent are
/// relative to the previous *received* packet).
final class RtcpTransportCc extends RtcpPacket {
  final int senderSsrc;
  final int mediaSsrc;
  final int baseSeq;
  final int referenceTimeMs; // will be encoded at 64ms resolution
  final int fbPktCount;
  final List<int?> recvDeltasUs; // full range, null = not received

  RtcpTransportCc({
    required this.senderSsrc,
    required this.mediaSsrc,
    required this.baseSeq,
    required this.referenceTimeMs,
    required this.fbPktCount,
    required this.recvDeltasUs,
  });

  // Symbol values for status chunks.
  static const _notReceived = 0; // 00
  static const _smallDelta = 1;  // 01: unsigned 1-byte (0–63.75ms)
  static const _largeDelta = 2;  // 10: signed 2-byte (±8191.75ms)

  Uint8List build() {
    final statusCount = recvDeltasUs.length;

    // 1. Classify each packet's symbol and encode its delta.
    final symbols = <int>[];
    final deltaBytes = <int>[];
    for (final d in recvDeltasUs) {
      if (d == null) {
        symbols.add(_notReceived);
      } else {
        final d250 = d ~/ 250; // multiples of 250µs (truncation, matching Pion)
        if (d250 >= 0 && d250 <= 255) {
          symbols.add(_smallDelta);
          deltaBytes.add(d250);
        } else {
          symbols.add(_largeDelta);
          final clamped = d250.clamp(-32768, 32767);
          deltaBytes.add((clamped >> 8) & 0xFF);
          deltaBytes.add(clamped & 0xFF);
        }
      }
    }

    // 2. Encode status chunks.
    //    Use run-length when all symbols in a run are the same,
    //    otherwise use 2-bit status vector (7 symbols per chunk).
    final statusChunks = <int>[];
    var i = 0;
    while (i < symbols.length) {
      // Check if a run-length chunk is efficient (≥7 identical symbols).
      final sym = symbols[i];
      var runLen = 1;
      while (i + runLen < symbols.length && symbols[i + runLen] == sym && runLen < 8191) {
        runLen++;
      }
      if (runLen >= 7) {
        // Run-length chunk: T=0 | SS(2 bits) | run_length(13 bits)
        statusChunks.add((sym << 13) | runLen);
        i += runLen;
      } else {
        // 2-bit status vector chunk: T=1 | S=1 | 7 × 2-bit symbols
        var chunk = (1 << 15) | (1 << 14); // T=1, S=1
        for (var j = 0; j < 7; j++) {
          final s = (i + j < symbols.length) ? symbols[i + j] : 0;
          chunk |= (s & 0x03) << (12 - j * 2);
        }
        statusChunks.add(chunk);
        i += 7;
      }
    }

    // 3. Compute total size and serialize.
    final headerLen = 20;
    final chunksLen = statusChunks.length * 2;
    final totalLen = headerLen + chunksLen + deltaBytes.length;
    final paddedTotal = (totalLen + 3) & ~3;
    final padBytes = paddedTotal - totalLen;

    final out = Uint8List(paddedTotal);
    // V=2, P=(1 if padded), FMT=15
    out[0] = (padBytes > 0 ? 0xA0 : 0x80) | 15;
    out[1] = 205; // PT=RTPFB
    final wordLen = (paddedTotal ~/ 4) - 1;
    out[2] = (wordLen >> 8) & 0xFF;
    out[3] = wordLen & 0xFF;
    _writeU32(out, 4, senderSsrc);
    _writeU32(out, 8, mediaSsrc);
    // Base sequence number + packet status count
    out[12] = (baseSeq >> 8) & 0xFF;
    out[13] = baseSeq & 0xFF;
    out[14] = (statusCount >> 8) & 0xFF;
    out[15] = statusCount & 0xFF;
    // Reference time (24 bits, 64ms resolution) + fb packet count (8 bits)
    final refTime = referenceTimeMs ~/ 64;
    out[16] = (refTime >> 16) & 0xFF;
    out[17] = (refTime >> 8) & 0xFF;
    out[18] = refTime & 0xFF;
    out[19] = fbPktCount & 0xFF;

    // Status chunks
    var off = 20;
    for (final chunk in statusChunks) {
      out[off++] = (chunk >> 8) & 0xFF;
      out[off++] = chunk & 0xFF;
    }

    // Recv deltas
    for (final d in deltaBytes) {
      out[off++] = d;
    }

    // RTCP padding: last byte is the padding count (including itself).
    if (padBytes > 0) {
      out[paddedTotal - 1] = padBytes;
    }

    return out;
  }
}

final class RtcpReportBlock {
  final int ssrc;
  final int fractionLost;
  final int cumulativeLost;
  final int extendedHighestSeq;
  final int jitter;
  final int lastSr;
  final int delaySinceLastSr;

  const RtcpReportBlock({
    required this.ssrc,
    required this.fractionLost,
    required this.cumulativeLost,
    required this.extendedHighestSeq,
    required this.jitter,
    required this.lastSr,
    required this.delaySinceLastSr,
  });
}

final class RtcpSdesChunk {
  final int ssrc;
  final Map<int, String> items; // type → value
  const RtcpSdesChunk({required this.ssrc, required this.items});
}

final class RtcpNackEntry {
  final int pid; // packet ID (sequence number)
  final int blp; // bitmask of following lost packets

  const RtcpNackEntry({required this.pid, required this.blp});
}

void _writeU32(Uint8List buf, int offset, int value) {
  buf[offset]     = (value >> 24) & 0xFF;
  buf[offset + 1] = (value >> 16) & 0xFF;
  buf[offset + 2] = (value >>  8) & 0xFF;
  buf[offset + 3] = value & 0xFF;
}
