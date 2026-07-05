import 'dart:typed_data';

import '../core/byte_io.dart';

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
    writeU16(out, 2, sequenceNumber);
    writeU32(out, 4, timestamp);
    writeU32(out, 8, ssrc);

    var offset = 12;
    for (final csrc in csrcs) {
      writeU32(out, offset, csrc);
      offset += 4;
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
    writeU16(out, 0, profile);
    writeU16(out, 2, padded ~/ 4);
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

/// RTCP packet type values (RFC 3550 §12.1, RFC 4585 §6.1).
abstract final class RtcpPacketType {
  RtcpPacketType._();

  static const int sr = 200;    // Sender Report
  static const int rr = 201;    // Receiver Report
  static const int sdes = 202;  // Source Description
  static const int bye = 203;   // Goodbye
  static const int rtpfb = 205; // Transport-layer feedback (NACK, TWCC)
  static const int psfb = 206;  // Payload-specific feedback (PLI, REMB)
}

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
    out[1] = RtcpPacketType.sr;
    writeU16(out, 2, (len ~/ 4) - 1);
    writeU32(out, 4, ssrc);
    writeU32(out, 8, ntpTimestampHigh);
    writeU32(out, 12, ntpTimestampLow);
    writeU32(out, 16, rtpTimestamp);
    writeU32(out, 20, packetCount);
    writeU32(out, 24, octetCount);
    var off = 28;
    for (final b in reportBlocks) {
      writeU32(out, off, b.ssrc); off += 4;
      out[off] = b.fractionLost & 0xFF;
      writeU24(out, off + 1, b.cumulativeLost);
      off += 4;
      writeU32(out, off, b.extendedHighestSeq); off += 4;
      writeU32(out, off, b.jitter); off += 4;
      writeU32(out, off, b.lastSr); off += 4;
      writeU32(out, off, b.delaySinceLastSr); off += 4;
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
    out[1] = RtcpPacketType.rr;
    writeU16(out, 2, (len ~/ 4) - 1);
    writeU32(out, 4, ssrc);
    var off = 8;
    for (final rb in reportBlocks) {
      writeU32(out, off, rb.ssrc); off += 4;
      out[off] = rb.fractionLost & 0xFF;
      writeU24(out, off + 1, rb.cumulativeLost);
      off += 4;
      writeU32(out, off, rb.extendedHighestSeq); off += 4;
      writeU32(out, off, rb.jitter); off += 4;
      writeU32(out, off, rb.lastSr); off += 4;
      writeU32(out, off, rb.delaySinceLastSr); off += 4;
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
    final body = ByteWriter();
    for (final chunk in chunks) {
      body.writeU32(chunk.ssrc);
      // SDES items: type(1) + length(1) + value
      for (final entry in chunk.items.entries) {
        final val = entry.value.codeUnits;
        body.writeU8(entry.key);
        body.writeU8(val.length);
        body.writeBytes(val);
      }
      body.writeU8(0); // end marker
      // Pad chunk to 4-byte boundary
      while (body.length % 4 != 0) { body.writeU8(0); }
    }
    final bodyBytes = body.takeBytes();
    final len = 4 + bodyBytes.length;
    final out = Uint8List(len);
    out[0] = 0x80 | (chunks.length & 0x1F); // V=2, SC
    out[1] = RtcpPacketType.sdes;
    writeU16(out, 2, (len ~/ 4) - 1);
    out.setRange(4, len, bodyBytes);
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
    out[1] = RtcpPacketType.psfb;
    writeU16(out, 2, 2); // length=2 (words)
    writeU32(out, 4, senderSsrc);
    writeU32(out, 8, mediaSourceSsrc);
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
    out[1] = RtcpPacketType.psfb;
    writeU16(out, 2, (len ~/ 4) - 1);
    writeU32(out, 4, senderSsrc);
    writeU32(out, 8, 0); // media SSRC = 0 for REMB
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
      writeU32(out, off, ssrc);
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
    final (symbols, deltaBytes) = _classifyDeltas();
    final statusChunks = _encodeStatusChunks(symbols);
    return _serialize(statusChunks, deltaBytes);
  }

  /// Classify each packet's symbol and encode its delta.
  (List<int> symbols, List<int> deltaBytes) _classifyDeltas() {
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
    return (symbols, deltaBytes);
  }

  /// Encode status chunks.
  ///
  /// Use run-length when all symbols in a run are the same,
  /// otherwise use 2-bit status vector (7 symbols per chunk).
  static List<int> _encodeStatusChunks(List<int> symbols) {
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
    return statusChunks;
  }

  /// Compute total size and serialize.
  Uint8List _serialize(List<int> statusChunks, List<int> deltaBytes) {
    final statusCount = recvDeltasUs.length;
    final headerLen = 20;
    final chunksLen = statusChunks.length * 2;
    final totalLen = headerLen + chunksLen + deltaBytes.length;
    final paddedTotal = (totalLen + 3) & ~3;
    final padBytes = paddedTotal - totalLen;

    final out = Uint8List(paddedTotal);
    // V=2, P=(1 if padded), FMT=15
    out[0] = (padBytes > 0 ? 0xA0 : 0x80) | 15;
    out[1] = RtcpPacketType.rtpfb;
    writeU16(out, 2, (paddedTotal ~/ 4) - 1);
    writeU32(out, 4, senderSsrc);
    writeU32(out, 8, mediaSsrc);
    // Base sequence number + packet status count
    writeU16(out, 12, baseSeq);
    writeU16(out, 14, statusCount);
    // Reference time (24 bits, 64ms resolution) + fb packet count (8 bits)
    writeU24(out, 16, referenceTimeMs ~/ 64);
    out[19] = fbPktCount & 0xFF;

    // Status chunks
    var off = 20;
    for (final chunk in statusChunks) {
      writeU16(out, off, chunk);
      off += 2;
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
