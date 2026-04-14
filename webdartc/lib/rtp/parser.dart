import 'dart:typed_data';

import '../core/result.dart';
import '../core/state_machine.dart' show ParseError;
import 'packet.dart';

export 'packet.dart';

/// RTP/RTCP demultiplexer and parser (RFC 3550).
abstract final class RtpParser {
  RtpParser._();

  /// True if [packet] is RTCP (payload type 64–95).
  ///
  /// RFC 5761 §4: PT in [64..95] → RTCP.
  static bool isRtcp(Uint8List packet) {
    if (packet.length < 2) return false;
    final pt = packet[1] & 0x7F;
    return pt >= 64 && pt <= 95;
  }

  /// True if [packet] is DTLS (first byte 20–63).
  static bool isDtls(Uint8List packet) {
    if (packet.isEmpty) return false;
    return packet[0] >= 20 && packet[0] <= 63;
  }

  /// Parse an RTP packet.
  static Result<RtpPacket, ParseError> parseRtp(Uint8List raw) {
    if (raw.length < 12) {
      return Err(const ParseError('RTP: packet too short'));
    }
    final version = (raw[0] >> 6) & 0x03;
    if (version != 2) {
      return Err(ParseError('RTP: invalid version $version'));
    }
    final padding   = (raw[0] & 0x20) != 0;
    final extension = (raw[0] & 0x10) != 0;
    final cc        = raw[0] & 0x0F;
    final marker    = (raw[1] & 0x80) != 0;
    final pt        = raw[1] & 0x7F;
    final seq       = _u16(raw, 2);
    final ts        = _u32(raw, 4);
    final ssrc      = _u32(raw, 8);

    if (raw.length < 12 + cc * 4) {
      return Err(const ParseError('RTP: truncated CSRC list'));
    }
    final csrcs = <int>[];
    for (var i = 0; i < cc; i++) {
      csrcs.add(_u32(raw, 12 + i * 4));
    }

    var offset = 12 + cc * 4;
    RtpExtension? ext;
    if (extension) {
      if (raw.length < offset + 4) {
        return Err(const ParseError('RTP: truncated extension'));
      }
      final profile = _u16(raw, offset);
      final extLenWords = _u16(raw, offset + 2);
      final extLen = extLenWords * 4;
      offset += 4;
      if (raw.length < offset + extLen) {
        return Err(const ParseError('RTP: truncated extension data'));
      }
      ext = RtpExtension(profile: profile, data: raw.sublist(offset, offset + extLen));
      offset += extLen;
    }

    var payloadEnd = raw.length;
    if (padding && raw.isNotEmpty) {
      final padLen = raw[raw.length - 1];
      payloadEnd -= padLen;
    }
    if (payloadEnd < offset) {
      return Err(const ParseError('RTP: invalid padding'));
    }

    return Ok(RtpPacket(
      version: version,
      padding: padding,
      extension: extension,
      csrcs: csrcs,
      marker: marker,
      payloadType: pt,
      sequenceNumber: seq,
      timestamp: ts,
      ssrc: ssrc,
      headerExtension: ext,
      payload: raw.sublist(offset, payloadEnd),
    ));
  }

  /// Parse one or more RTCP packets from a compound RTCP packet.
  static Result<List<RtcpPacket>, ParseError> parseRtcp(Uint8List raw) {
    final packets = <RtcpPacket>[];
    var offset = 0;
    while (offset < raw.length) {
      if (raw.length - offset < 4) break;
      final rc  = raw[offset] & 0x1F;
      final pt  = raw[offset + 1];
      final len = (_u16(raw, offset + 2) + 1) * 4;
      if (offset + len > raw.length) break;
      final body = raw.sublist(offset, offset + len);
      offset += len;

      final parsed = _parseOneRtcp(pt, rc, body);
      if (parsed != null) packets.add(parsed);
    }
    if (packets.isEmpty) {
      return Err(const ParseError('RTCP: no valid packets'));
    }
    return Ok(packets);
  }

  static RtcpPacket? _parseOneRtcp(int pt, int rc, Uint8List body) {
    switch (pt) {
      case 200: return _parseSr(body, rc);
      case 201: return _parseRr(body, rc);
      case 202: return _parseSdes(body, rc);
      case 203: return _parseBye(body, rc);
      case 205: return _parseFb(body, rc, pt);  // RTPFB
      case 206: return _parseFb(body, rc, pt);  // PSFB
      default:  return null;
    }
  }

  static RtcpSenderReport _parseSr(Uint8List body, int rc) {
    if (body.length < 28) return RtcpSenderReport(ssrc: 0, ntpTimestampHigh: 0, ntpTimestampLow: 0, rtpTimestamp: 0, packetCount: 0, octetCount: 0);
    final ssrc  = _u32(body, 4);
    final ntpHi = _u32(body, 8);
    final ntpLo = _u32(body, 12);
    final rtpTs = _u32(body, 16);
    final pkts  = _u32(body, 20);
    final octs  = _u32(body, 24);
    final rbs = _parseReportBlocks(body, 28, rc);
    return RtcpSenderReport(
      ssrc: ssrc,
      ntpTimestampHigh: ntpHi,
      ntpTimestampLow: ntpLo,
      rtpTimestamp: rtpTs,
      packetCount: pkts,
      octetCount: octs,
      reportBlocks: rbs,
    );
  }

  static RtcpReceiverReport _parseRr(Uint8List body, int rc) {
    if (body.length < 8) return RtcpReceiverReport(ssrc: 0);
    final ssrc = _u32(body, 4);
    final rbs = _parseReportBlocks(body, 8, rc);
    return RtcpReceiverReport(ssrc: ssrc, reportBlocks: rbs);
  }

  static List<RtcpReportBlock> _parseReportBlocks(Uint8List body, int offset, int count) {
    final blocks = <RtcpReportBlock>[];
    for (var i = 0; i < count && offset + 24 <= body.length; i++) {
      blocks.add(RtcpReportBlock(
        ssrc: _u32(body, offset),
        fractionLost: body[offset + 4],
        cumulativeLost: (body[offset + 5] << 16) | (body[offset + 6] << 8) | body[offset + 7],
        extendedHighestSeq: _u32(body, offset + 8),
        jitter: _u32(body, offset + 12),
        lastSr: _u32(body, offset + 16),
        delaySinceLastSr: _u32(body, offset + 20),
      ));
      offset += 24;
    }
    return blocks;
  }

  static RtcpSdes _parseSdes(Uint8List body, int rc) {
    final chunks = <RtcpSdesChunk>[];
    var offset = 4;
    for (var i = 0; i < rc && offset + 4 <= body.length; i++) {
      final ssrc = _u32(body, offset);
      offset += 4;
      final items = <int, String>{};
      while (offset < body.length) {
        final type = body[offset++];
        if (type == 0) { // END
          // pad to 4-byte boundary
          while (offset % 4 != 0) { offset++; }
          break;
        }
        if (offset >= body.length) break;
        final len = body[offset++];
        if (offset + len > body.length) break;
        items[type] = String.fromCharCodes(body.sublist(offset, offset + len));
        offset += len;
      }
      chunks.add(RtcpSdesChunk(ssrc: ssrc, items: items));
    }
    return RtcpSdes(chunks: chunks);
  }

  static RtcpBye _parseBye(Uint8List body, int rc) {
    final ssrcs = <int>[];
    var offset = 4;
    for (var i = 0; i < rc && offset + 4 <= body.length; i++) {
      ssrcs.add(_u32(body, offset));
      offset += 4;
    }
    return RtcpBye(ssrcs: ssrcs);
  }

  static RtcpPacket? _parseFb(Uint8List body, int fmt, int pt) {
    if (body.length < 12) return null;
    final senderSsrc = _u32(body, 4);
    final mediaSsrc  = _u32(body, 8);

    if (pt == 205 && fmt == 1) {
      // Generic NACK
      final nacks = <RtcpNackEntry>[];
      var offset = 12;
      while (offset + 4 <= body.length) {
        nacks.add(RtcpNackEntry(
          pid: _u16(body, offset),
          blp: _u16(body, offset + 2),
        ));
        offset += 4;
      }
      return RtcpNack(
        senderSsrc: senderSsrc,
        mediaSourceSsrc: mediaSsrc,
        nacks: nacks,
      );
    }
    if (pt == 206 && fmt == 1) {
      return RtcpPli(senderSsrc: senderSsrc, mediaSourceSsrc: mediaSsrc);
    }
    return null;
  }

  static int _u16(Uint8List d, int o) => (d[o] << 8) | d[o + 1];
  static int _u32(Uint8List d, int o) =>
      ((d[o] << 24) | (d[o+1] << 16) | (d[o+2] << 8) | d[o+3]) >>> 0;
}
