/// RTP payload packetizer/depacketizer interfaces and implementations.
///
/// Converts between encoded media chunks and RTP-sized payloads.
library;

import 'dart:typed_data';

import '../codec/video_codec.dart';
import '../codec/audio_codec.dart';

// ── Interfaces ──────────────────────────────────────────────────────────────

/// Splits an encoded frame into one or more RTP payloads.
abstract interface class PayloadPacketizer {
  /// Returns a list of (payload, marker) pairs. The last fragment has marker=true.
  List<(Uint8List payload, bool marker)> packetize(
    Uint8List encodedData, {
    required bool isKeyFrame,
  });
}

/// Reassembles RTP payloads into encoded frames.
abstract interface class VideoPayloadDepacketizer {
  /// Feed an RTP payload. Returns a completed [EncodedVideoChunk] when
  /// a full frame is assembled (marker=true), null otherwise.
  EncodedVideoChunk? depacketize(Uint8List rtpPayload, {
    required bool marker,
    required int timestamp,
  });
}

/// Audio depacketizer — typically trivial (one chunk per packet).
abstract interface class AudioPayloadDepacketizer {
  EncodedAudioChunk? depacketize(Uint8List rtpPayload, {
    required int timestamp,
  });
}

// ── VP8 Packetizer (RFC 7741) ───────────────────────────────────────────────

/// VP8 RTP payload format packetizer (RFC 7741 §4).
///
/// VP8 payload descriptor (minimal, 1 byte):
///   X R N S PartID(4)
///   X=0 (no extension), S=1 for first partition, PartID=0.
///
/// For fragmented frames, only the first fragment has S=1.
final class Vp8Packetizer implements PayloadPacketizer {
  final int maxPayloadSize;

  Vp8Packetizer({this.maxPayloadSize = 1200});

  @override
  List<(Uint8List payload, bool marker)> packetize(
    Uint8List encodedData, {
    required bool isKeyFrame,
  }) {
    if (encodedData.isEmpty) return const [];

    final results = <(Uint8List, bool)>[];
    var offset = 0;
    var isFirst = true;

    while (offset < encodedData.length) {
      // Reserve 1 byte for VP8 payload descriptor
      final maxChunk = maxPayloadSize - 1;
      final remaining = encodedData.length - offset;
      final chunkSize = remaining > maxChunk ? maxChunk : remaining;
      final isLast = (offset + chunkSize) >= encodedData.length;

      // VP8 payload descriptor (1 byte, no extensions)
      // Bit 4 (S): 1 if this is the start of a VP8 partition
      final descriptor = isFirst ? 0x10 : 0x00; // S=1 for first fragment

      final payload = Uint8List(1 + chunkSize);
      payload[0] = descriptor;
      payload.setRange(1, 1 + chunkSize, encodedData, offset);

      results.add((payload, isLast));
      offset += chunkSize;
      isFirst = false;
    }

    return results;
  }
}

/// VP8 RTP payload format depacketizer (RFC 7741).
final class Vp8Depacketizer implements VideoPayloadDepacketizer {
  final _fragments = <int>[];

  @override
  EncodedVideoChunk? depacketize(Uint8List rtpPayload, {
    required bool marker,
    required int timestamp,
  }) {
    if (rtpPayload.isEmpty) return null;

    // Parse VP8 payload descriptor
    var offset = 0;
    final firstByte = rtpPayload[0];
    offset++; // skip descriptor byte

    // X bit (bit 7) — extended fields present
    if ((firstByte & 0x80) != 0 && rtpPayload.length > offset) {
      final xByte = rtpPayload[offset++];
      // I bit — PictureID present
      if ((xByte & 0x80) != 0 && rtpPayload.length > offset) {
        if ((rtpPayload[offset] & 0x80) != 0) {
          offset += 2; // 16-bit PictureID
        } else {
          offset += 1; // 8-bit PictureID
        }
      }
      // L bit — TL0PICIDX present
      if ((xByte & 0x40) != 0 && rtpPayload.length > offset) offset++;
      // T/K bits — TID/KEYIDX present
      if (((xByte & 0x20) != 0 || (xByte & 0x10) != 0) && rtpPayload.length > offset) {
        offset++;
      }
    }

    if (offset >= rtpPayload.length) return null;

    // Accumulate payload bytes (after descriptor)
    final payloadBytes = rtpPayload.sublist(offset);
    _fragments.addAll(payloadBytes);

    if (!marker) return null; // more fragments coming

    // Complete frame — determine key/delta from VP8 bitstream
    final frameData = Uint8List.fromList(_fragments);
    _fragments.clear();

    // VP8 keyframe detection: first byte bit 0 = 0 means keyframe
    final isKey = frameData.isNotEmpty && (frameData[0] & 0x01) == 0;

    return EncodedVideoChunk(
      type: isKey ? EncodedVideoChunkType.key : EncodedVideoChunkType.delta,
      timestamp: timestamp,
      data: frameData,
    );
  }
}

// ── H.264 Packetizer (RFC 6184) ─────────────────────────────────────────────

/// Splits an Annex B H.264 byte-stream into individual NAL units.
///
/// Start codes `00 00 01` or `00 00 00 01` delimit NAL units; this function
/// strips them and returns the NAL payloads (including the NAL header byte).
List<Uint8List> splitH264AnnexB(Uint8List data) {
  final starts = <(int, int)>[]; // (payload_start, startcode_len)
  var i = 0;
  while (i <= data.length - 3) {
    if (data[i] == 0 && data[i + 1] == 0) {
      if (data[i + 2] == 1) {
        starts.add((i + 3, 3));
        i += 3;
        continue;
      }
      if (i + 3 < data.length &&
          data[i + 2] == 0 &&
          data[i + 3] == 1) {
        starts.add((i + 4, 4));
        i += 4;
        continue;
      }
    }
    i++;
  }
  final nals = <Uint8List>[];
  for (var k = 0; k < starts.length; k++) {
    final start = starts[k].$1;
    final end = k + 1 < starts.length
        ? starts[k + 1].$1 - starts[k + 1].$2
        : data.length;
    if (end > start) nals.add(Uint8List.sublistView(data, start, end));
  }
  return nals;
}

/// H.264 RTP payload format packetizer (RFC 6184).
///
/// - Single NAL units that fit in [maxPayloadSize] are sent as-is (§5.4).
/// - Larger NAL units are split using FU-A fragmentation (§5.8).
/// - Marker=true is set on the RTP packet carrying the last fragment of the
///   last NAL unit of the frame.
final class H264Packetizer implements PayloadPacketizer {
  final int maxPayloadSize;

  H264Packetizer({this.maxPayloadSize = 1200});

  @override
  List<(Uint8List payload, bool marker)> packetize(
    Uint8List encodedData, {
    required bool isKeyFrame,
  }) {
    if (encodedData.isEmpty) return const [];
    final nals = splitH264AnnexB(encodedData);
    if (nals.isEmpty) return const [];

    final packets = <(Uint8List, bool)>[];
    for (var i = 0; i < nals.length; i++) {
      final isLastNal = i == nals.length - 1;
      final nal = nals[i];
      if (nal.length <= maxPayloadSize) {
        // Single NAL unit packet.
        packets.add((Uint8List.fromList(nal), isLastNal));
      } else {
        // FU-A fragmentation.
        final header = nal[0];
        final fuIndicator = (header & 0xE0) | 28; // preserve F/NRI, type = FU-A
        final nalType = header & 0x1F;
        final body = Uint8List.sublistView(nal, 1);
        final chunkSize = maxPayloadSize - 2; // minus FU ind + FU header
        var off = 0;
        var first = true;
        while (off < body.length) {
          final remaining = body.length - off;
          final take = remaining > chunkSize ? chunkSize : remaining;
          final last = (off + take) >= body.length;
          final fuHeader =
              (first ? 0x80 : 0) | (last ? 0x40 : 0) | nalType;
          final pkt = Uint8List(2 + take);
          pkt[0] = fuIndicator;
          pkt[1] = fuHeader;
          pkt.setRange(2, 2 + take, body, off);
          packets.add((pkt, isLastNal && last));
          off += take;
          first = false;
        }
      }
    }
    return packets;
  }
}

/// H.264 RTP payload format depacketizer (RFC 6184).
///
/// Reassembles Single NAL unit and FU-A packets into an Annex B byte-stream.
/// STAP-A/B, MTAP, and interleaved modes are not supported.
final class H264Depacketizer implements VideoPayloadDepacketizer {
  static const _startCode = [0, 0, 0, 1];

  final List<Uint8List> _nals = [];
  final List<int> _fuBuffer = [];
  int _fuHeaderByte = 0;
  bool _fuStarted = false;

  @override
  EncodedVideoChunk? depacketize(Uint8List payload, {
    required bool marker,
    required int timestamp,
  }) {
    if (payload.isEmpty) return null;
    final type = payload[0] & 0x1F;

    if (type >= 1 && type <= 23) {
      _nals.add(Uint8List.fromList(payload));
    } else if (type == 24) {
      // STAP-A (RFC 6184 §5.7.1): a single RTP payload carrying multiple
      // NAL units. Layout after the STAP-A header byte:
      //   [ 2-byte BE size | N bytes NAL unit ]  repeated
      var off = 1;
      while (off + 2 <= payload.length) {
        final size = (payload[off] << 8) | payload[off + 1];
        off += 2;
        if (size == 0 || off + size > payload.length) break;
        _nals.add(Uint8List.sublistView(payload, off, off + size));
        off += size;
      }
    } else if (type == 28) {
      if (payload.length < 2) return null;
      final fuHeader = payload[1];
      final start = (fuHeader & 0x80) != 0;
      final end = (fuHeader & 0x40) != 0;
      final nalType = fuHeader & 0x1F;
      if (start) {
        _fuBuffer.clear();
        _fuHeaderByte = (payload[0] & 0xE0) | nalType;
        _fuBuffer.add(_fuHeaderByte);
        _fuStarted = true;
      }
      if (_fuStarted) {
        _fuBuffer.addAll(payload.sublist(2));
        if (end) {
          _nals.add(Uint8List.fromList(_fuBuffer));
          _fuBuffer.clear();
          _fuStarted = false;
        }
      }
    }
    // STAP-B (25), MTAP (26/27), FU-B (29) — unsupported; silently skip.

    if (!marker) return null;

    var isKey = false;
    var size = 0;
    for (final n in _nals) {
      size += _startCode.length + n.length;
      final t = n[0] & 0x1F;
      if (t == 5) isKey = true; // IDR slice
    }
    final out = Uint8List(size);
    var w = 0;
    for (final n in _nals) {
      out.setRange(w, w + _startCode.length, _startCode);
      w += _startCode.length;
      out.setRange(w, w + n.length, n);
      w += n.length;
    }
    _nals.clear();

    return EncodedVideoChunk(
      type: isKey ? EncodedVideoChunkType.key : EncodedVideoChunkType.delta,
      timestamp: timestamp,
      data: out,
    );
  }
}

// ── JPEG over RTP (RFC 2435) ────────────────────────────────────────────────

/// JPEG RTP payload format (RFC 2435).
///
/// Targets the camera-passthrough use case: forwarding a UVC / built-in
/// camera's native MJPEG stream onto the wire without re-encoding. Only
/// the subset RFC 2435 actually defines for live video is supported:
///
/// - Baseline 8-bit JPEG (SOF0, precision=8)
/// - YCbCr 4:2:2 (Type=0) or 4:2:0 (Type=1) sampling
/// - Width and height multiples of 8, ≤ 2040 px
/// - Up to two quantization tables (Y + C), 8-bit precision
///
/// Progressive JPEG, arithmetic coding, lossless mode, 4:4:4, 16-bit
/// quantization, and JPEG2000 are rejected at packetize() time with an
/// [ArgumentError]; none of those appear on real-world UVC MJPEG sources.
///
/// Dimensions are encoded in 8-pixel units per RFC 2435 §3.1.5; height /
/// width of 2048 wraps to 0 per the spec.
const int _jpegRtpQDynamic = 255;
const int _jpegRtpMainHeaderLen = 8;
const int _jpegRtpRstHeaderLen = 4;

/// Standard Huffman tables from JPEG Annex K (Tables K.3 / K.5). RFC 2435
/// Appendix B references them: senders strip DHT segments off the wire,
/// and receivers reconstruct them from these constants so every JPEG that
/// goes through the depacketizer has its Huffman tables in the standard
/// form regardless of what the camera emitted.
const List<int> _lumDcCodelens = [
  0, 0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
];
const List<int> _lumDcSymbols = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
];
const List<int> _lumAcCodelens = [
  0, 0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d,
];
const List<int> _lumAcSymbols = [
  0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
  0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08,
  0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72,
  0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
  0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45,
  0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
  0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75,
  0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
  0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3,
  0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
  0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
  0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
  0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4,
  0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
];
const List<int> _chmDcCodelens = [
  0, 0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
];
const List<int> _chmDcSymbols = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
];
const List<int> _chmAcCodelens = [
  0, 0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77,
];
const List<int> _chmAcSymbols = [
  0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41,
  0x51, 0x07, 0x61, 0x71, 0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91,
  0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0, 0x15, 0x62, 0x72, 0xd1,
  0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
  0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44,
  0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
  0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74,
  0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
  0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4,
  0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
  0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
  0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4,
  0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
];

/// Parsed view of a baseline JPEG sufficient for RFC 2435 packetization.
final class _ParsedJpeg {
  final int width;
  final int height;
  /// RFC 2435 Type field — 0 = 4:2:2 progressive, 1 = 4:2:0 progressive
  /// (the +64 restart bias is added by the packetizer when DRI is set).
  final int type;
  final int? restartInterval;
  /// Concatenated 8-bit quantization tables (Y then C). 64 bytes each.
  final Uint8List quantTables;
  /// Entropy-coded segment between end-of-SOS-header and EOI marker
  /// (inclusive of any embedded RST markers).
  final Uint8List entropyData;

  const _ParsedJpeg({
    required this.width,
    required this.height,
    required this.type,
    required this.restartInterval,
    required this.quantTables,
    required this.entropyData,
  });
}

/// Parses a baseline JPEG byte stream into the fields RFC 2435 needs.
/// Throws [ArgumentError] for any feature the packetizer doesn't support
/// (non-baseline, non-8-bit, sampling != 4:2:0/4:2:2, etc.).
_ParsedJpeg _parseJpeg(Uint8List jpeg) {
  if (jpeg.length < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8) {
    throw ArgumentError('Not a JPEG (missing SOI)');
  }
  int? width;
  int? height;
  int? rtpType;
  int? restartInterval;
  // 8 bytes for the table-class/dest byte + 64 bytes of QT data, per table.
  // The wire format keeps tables in zig-zag order — we forward the bytes
  // exactly as they appear in DQT segments so the receiver's reconstructed
  // DQT round-trips losslessly.
  final qtByDest = <int, Uint8List>{};
  Uint8List? entropy;

  var i = 2;
  while (i + 1 < jpeg.length) {
    if (jpeg[i] != 0xFF) {
      throw ArgumentError('Invalid JPEG: expected marker at offset $i');
    }
    // Skip fill bytes (multiple 0xFF before a marker is allowed by spec).
    while (i + 1 < jpeg.length && jpeg[i + 1] == 0xFF) {
      i++;
    }
    if (i + 1 >= jpeg.length) break;
    final marker = jpeg[i + 1];
    i += 2;

    if (marker == 0xD8) continue; // SOI (already consumed)
    if (marker == 0xD9) break; // EOI
    if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
      // Standalone markers (TEM / RSTn) — no length / data follows.
      continue;
    }

    if (i + 1 >= jpeg.length) {
      throw ArgumentError('Truncated JPEG: marker 0x${marker.toRadixString(16)} '
          'missing length');
    }
    final segLen = (jpeg[i] << 8) | jpeg[i + 1];
    if (segLen < 2 || i + segLen > jpeg.length) {
      throw ArgumentError('Invalid JPEG: bad segment length $segLen at $i');
    }
    final segStart = i + 2;
    final segEnd = i + segLen; // exclusive
    i = segEnd;

    switch (marker) {
      case 0xC0: // SOF0 — baseline DCT
        if (segEnd - segStart < 6) {
          throw ArgumentError('SOF0 too short');
        }
        final precision = jpeg[segStart];
        if (precision != 8) {
          throw ArgumentError('Only 8-bit JPEG is supported (got $precision)');
        }
        height = (jpeg[segStart + 1] << 8) | jpeg[segStart + 2];
        width = (jpeg[segStart + 3] << 8) | jpeg[segStart + 4];
        final nComponents = jpeg[segStart + 5];
        if (nComponents != 3) {
          throw ArgumentError('Only 3-component YCbCr is supported '
              '(got $nComponents components)');
        }
        if (segEnd - segStart < 6 + nComponents * 3) {
          throw ArgumentError('SOF0 truncated');
        }
        // Read sampling factors. Y is the first component listed; we infer
        // RFC 2435 Type from Y's H/V (Cb/Cr are required to be 1×1).
        final yHv = jpeg[segStart + 6 + 1];
        final yH = (yHv >> 4) & 0x0F;
        final yV = yHv & 0x0F;
        if (yH == 2 && yV == 1) {
          rtpType = 0; // 4:2:2
        } else if (yH == 2 && yV == 2) {
          rtpType = 1; // 4:2:0
        } else {
          throw ArgumentError('Unsupported chroma sampling '
              '(Y H=$yH V=$yV) — only 4:2:0 and 4:2:2 are supported');
        }
      case 0xC1:
      case 0xC2:
      case 0xC3:
      case 0xC5:
      case 0xC6:
      case 0xC7:
      case 0xC9:
      case 0xCA:
      case 0xCB:
      case 0xCD:
      case 0xCE:
      case 0xCF:
        throw ArgumentError('Non-baseline JPEG (SOF marker 0x'
            '${marker.toRadixString(16)}) is not supported');
      case 0xDB: // DQT — may contain multiple tables back-to-back
        var p = segStart;
        while (p < segEnd) {
          final pq = (jpeg[p] >> 4) & 0x0F; // precision: 0 = 8-bit
          final tq = jpeg[p] & 0x0F; // destination
          p++;
          if (pq != 0) {
            throw ArgumentError('16-bit quantization tables not supported');
          }
          if (p + 64 > segEnd) {
            throw ArgumentError('DQT segment truncated');
          }
          qtByDest[tq] = Uint8List.fromList(jpeg.sublist(p, p + 64));
          p += 64;
        }
      case 0xDD: // DRI
        if (segEnd - segStart != 2) {
          throw ArgumentError('DRI segment must be 2 bytes');
        }
        restartInterval = (jpeg[segStart] << 8) | jpeg[segStart + 1];
      case 0xDA: // SOS — entropy data follows until EOI
        // Find EOI by scanning. Escape sequence 0xFF 0x00 stays in the
        // entropy bytes; markers within entropy other than RSTn / EOI are
        // not legal in baseline JPEG.
        var scan = segEnd;
        while (scan + 1 < jpeg.length) {
          if (jpeg[scan] == 0xFF) {
            final next = jpeg[scan + 1];
            if (next == 0x00) {
              scan += 2; // escaped 0xFF byte
              continue;
            }
            if (next >= 0xD0 && next <= 0xD7) {
              scan += 2; // RSTn — keep inline
              continue;
            }
            if (next == 0xFF) {
              scan++; // fill byte
              continue;
            }
            // Any other marker terminates the entropy stream.
            break;
          }
          scan++;
        }
        entropy = Uint8List.fromList(jpeg.sublist(segEnd, scan));
        i = scan;
      default:
        // Skip APP0..APP15 (E0..EF), COM (FE), DHT (C4), and anything else
        // we don't need to interpret — RFC 2435 reconstructs DHT on the
        // receive side from fixed tables, and APPn / COM are dropped.
        break;
    }
    if (entropy != null) break;
  }

  if (width == null || height == null || rtpType == null) {
    throw ArgumentError('JPEG missing SOF0');
  }
  if (entropy == null) {
    throw ArgumentError('JPEG missing SOS / entropy data');
  }
  // Component-0 (Y) uses dest 0, components 1/2 (Cb/Cr) typically share
  // dest 1; we forward whichever two tables the encoder emitted, padding
  // with table-0 if a Cb/Cr table is missing (rare but spec-permitted).
  final yTable = qtByDest[0];
  if (yTable == null) {
    throw ArgumentError('JPEG missing luminance quantization table');
  }
  final cTable = qtByDest[1] ?? yTable;
  final combined = Uint8List(128);
  combined.setRange(0, 64, yTable);
  combined.setRange(64, 128, cTable);

  if (width % 8 != 0 || height % 8 != 0) {
    throw ArgumentError('JPEG dimensions must be multiples of 8 '
        '(got ${width}x$height)');
  }
  if (width > 2040 || height > 2040) {
    throw ArgumentError('RFC 2435 only supports dimensions ≤ 2040 '
        '(got ${width}x$height)');
  }

  return _ParsedJpeg(
    width: width,
    height: height,
    type: rtpType,
    restartInterval: restartInterval,
    quantTables: combined,
    entropyData: entropy,
  );
}

/// JPEG (MJPEG) RTP packetizer per RFC 2435 §3.
///
/// Emits dynamic-quantization-table packets (Q=255). The first packet of
/// each frame carries the quantization-table header (and a restart-marker
/// header if the source JPEG has DRI); subsequent packets carry only the
/// 8-byte main JPEG/RTP header.
final class JpegPacketizer implements PayloadPacketizer {
  final int maxPayloadSize;

  JpegPacketizer({this.maxPayloadSize = 1200});

  @override
  List<(Uint8List payload, bool marker)> packetize(
    Uint8List encodedData, {
    required bool isKeyFrame,
  }) {
    if (encodedData.isEmpty) return const [];
    final p = _parseJpeg(encodedData);

    // RFC 2435 §3.1.5 — width/height in 8-pixel units, 0 means 2048.
    final wUnits = (p.width == 2048) ? 0 : (p.width ~/ 8);
    final hUnits = (p.height == 2048) ? 0 : (p.height ~/ 8);

    // Type biases: +64 when a Restart Marker header is present.
    final hasRst = p.restartInterval != null;
    final type = p.type + (hasRst ? 64 : 0);

    // Quantization Table header: MBZ(1) + Precision(1) + Length(2) + tables.
    // Precision byte is 0 for two 8-bit tables (bit 0 = Y, bit 1 = C).
    final qtHeader = Uint8List(4 + p.quantTables.length);
    qtHeader[0] = 0; // MBZ
    qtHeader[1] = 0; // Precision (both tables 8-bit)
    qtHeader[2] = (p.quantTables.length >> 8) & 0xFF;
    qtHeader[3] = p.quantTables.length & 0xFF;
    qtHeader.setRange(4, qtHeader.length, p.quantTables);

    // Restart Marker header: 16-bit DRI, F=1, L=1, count=0x3FFF — tells the
    // receiver "fragments may split anywhere; reassemble by Fragment Offset
    // alone". RFC 2435 §3.1.7 endorses this for senders that don't align
    // packet boundaries to restart intervals.
    Uint8List? rstHeader;
    if (hasRst) {
      final dri = p.restartInterval!;
      rstHeader = Uint8List(_jpegRtpRstHeaderLen);
      rstHeader[0] = (dri >> 8) & 0xFF;
      rstHeader[1] = dri & 0xFF;
      rstHeader[2] = 0xFF; // F=1, L=1, top 6 bits of count = 0x3F
      rstHeader[3] = 0xFF; // low 8 bits of count = 0xFF
    }

    final out = <(Uint8List, bool)>[];
    var offset = 0;
    while (offset < p.entropyData.length) {
      final isFirst = offset == 0;
      final extraHeaderLen =
          (isFirst ? qtHeader.length : 0) + (isFirst && hasRst ? rstHeader!.length : 0);
      final headerLen = _jpegRtpMainHeaderLen + extraHeaderLen;
      final maxChunk = maxPayloadSize - headerLen;
      if (maxChunk <= 0) {
        throw StateError('maxPayloadSize=$maxPayloadSize too small for '
            'JPEG/RTP headers ($headerLen bytes)');
      }
      final remaining = p.entropyData.length - offset;
      final take = remaining > maxChunk ? maxChunk : remaining;
      final isLast = (offset + take) >= p.entropyData.length;

      final pkt = Uint8List(headerLen + take);
      var w = 0;
      // Main JPEG/RTP header (RFC 2435 §3.1)
      pkt[w++] = 0; // Type-specific
      pkt[w++] = (offset >> 16) & 0xFF;
      pkt[w++] = (offset >> 8) & 0xFF;
      pkt[w++] = offset & 0xFF;
      pkt[w++] = type;
      pkt[w++] = _jpegRtpQDynamic;
      pkt[w++] = wUnits;
      pkt[w++] = hUnits;
      if (isFirst) {
        if (hasRst) {
          pkt.setRange(w, w + rstHeader!.length, rstHeader);
          w += rstHeader.length;
        }
        pkt.setRange(w, w + qtHeader.length, qtHeader);
        w += qtHeader.length;
      }
      pkt.setRange(w, w + take, p.entropyData, offset);
      out.add((pkt, isLast));
      offset += take;
    }
    return out;
  }
}

/// JPEG (MJPEG) RTP depacketizer per RFC 2435 §3 + Appendix B.
///
/// Reassembles fragments into a baseline JFIF JPEG byte stream that any
/// conforming decoder can consume. Reconstructed JPEGs always carry the
/// standard JPEG Annex K Huffman tables (DHT segments are not on the wire
/// per RFC 2435 Appendix B), and the quantization tables come from the
/// per-frame QT header.
final class JpegDepacketizer implements VideoPayloadDepacketizer {
  final List<int> _entropy = [];
  Uint8List? _quantTables;
  int? _width;
  int? _height;
  int? _type;
  int? _restartInterval;
  int _expectedOffset = 0;
  bool _aborted = false;

  void _reset() {
    _entropy.clear();
    _quantTables = null;
    _width = null;
    _height = null;
    _type = null;
    _restartInterval = null;
    _expectedOffset = 0;
    _aborted = false;
  }

  @override
  EncodedVideoChunk? depacketize(Uint8List payload, {
    required bool marker,
    required int timestamp,
  }) {
    if (payload.length < _jpegRtpMainHeaderLen) return null;

    final fragmentOffset =
        (payload[1] << 16) | (payload[2] << 8) | payload[3];
    final rawType = payload[4];
    final q = payload[5];
    final wUnits = payload[6];
    final hUnits = payload[7];
    var p = _jpegRtpMainHeaderLen;

    if (fragmentOffset == 0) {
      _reset();
      _type = rawType & 0x3F; // strip the +64 restart bias
      _width = (wUnits == 0 ? 2048 : wUnits * 8);
      _height = (hUnits == 0 ? 2048 : hUnits * 8);

      // Restart Marker header (RFC 2435 §3.1.7) appears when Type ≥ 64.
      if (rawType >= 64) {
        if (payload.length < p + _jpegRtpRstHeaderLen) return null;
        _restartInterval = (payload[p] << 8) | payload[p + 1];
        p += _jpegRtpRstHeaderLen;
      }

      // Quantization Table header (RFC 2435 §3.1.8) appears when Q ≥ 128.
      // For Q ∈ [1, 99] RFC 2435 Appendix A defines synthesized tables;
      // we don't currently support those — the packetizer above always
      // emits Q=255, and that's the only Q a depacketizer in this
      // peer-pair scenario will see in practice.
      if (q >= 128) {
        if (payload.length < p + 4) return null;
        final precision = payload[p + 1];
        final length = (payload[p + 2] << 8) | payload[p + 3];
        p += 4;
        if (precision != 0) {
          _aborted = true; // 16-bit precision tables not supported
        } else if (length != 128 && length != 64) {
          _aborted = true;
        } else if (payload.length < p + length) {
          return null;
        } else {
          // Length=64 means a single shared luma+chroma table; pad with a
          // copy of itself so the receiver always emits two DQT entries.
          if (length == 64) {
            final t = Uint8List(128);
            t.setRange(0, 64, payload.sublist(p, p + 64));
            t.setRange(64, 128, payload.sublist(p, p + 64));
            _quantTables = t;
          } else {
            _quantTables = Uint8List.fromList(payload.sublist(p, p + 128));
          }
          p += length;
        }
      } else {
        _aborted = true; // Q < 128 (static tables from RFC 2435 Annex A)
      }
    } else if (_width == null) {
      // We never saw fragment offset 0 — drop this frame.
      _aborted = true;
    } else if (fragmentOffset != _expectedOffset) {
      // Out-of-order or lost packet; abandon reassembly so we don't emit a
      // corrupt JPEG. The next fragment offset=0 will reset state.
      _aborted = true;
    }

    if (!_aborted) {
      _entropy.addAll(payload.sublist(p));
      _expectedOffset = fragmentOffset + (payload.length - p);
    }

    if (!marker) return null;

    if (_aborted || _quantTables == null) {
      _reset();
      return null;
    }
    final jpeg = _assembleJpeg(
      width: _width!,
      height: _height!,
      type: _type!,
      restartInterval: _restartInterval,
      quantTables: _quantTables!,
      entropy: _entropy,
    );
    _reset();
    return EncodedVideoChunk(
      type: EncodedVideoChunkType.key, // every MJPEG frame is self-contained
      timestamp: timestamp,
      data: jpeg,
    );
  }
}

/// Builds a self-contained baseline JFIF JPEG from the fields the
/// depacketizer accumulated. Matches RFC 2435 Appendix B's MakeHeaders /
/// MakeQuantHeader / MakeHuffmanHeader / MakeDRIHeader layout.
Uint8List _assembleJpeg({
  required int width,
  required int height,
  required int type,
  required int? restartInterval,
  required Uint8List quantTables,
  required List<int> entropy,
}) {
  final b = BytesBuilder(copy: false);
  // SOI
  b.addByte(0xFF);
  b.addByte(0xD8);
  // DQT: one segment containing both Y and C tables (8-bit, dest 0 and 1)
  b.addByte(0xFF);
  b.addByte(0xDB);
  final dqtLen = 2 + 2 * (1 + 64);
  b.addByte((dqtLen >> 8) & 0xFF);
  b.addByte(dqtLen & 0xFF);
  b.addByte(0x00); // Pq=0 (8-bit), Tq=0 (luma)
  b.add(quantTables.sublist(0, 64));
  b.addByte(0x01); // Pq=0, Tq=1 (chroma)
  b.add(quantTables.sublist(64, 128));
  // DRI (optional)
  if (restartInterval != null) {
    b.addByte(0xFF);
    b.addByte(0xDD);
    b.addByte(0x00);
    b.addByte(0x04);
    b.addByte((restartInterval >> 8) & 0xFF);
    b.addByte(restartInterval & 0xFF);
  }
  // SOF0
  b.addByte(0xFF);
  b.addByte(0xC0);
  const sofLen = 8 + 3 * 3;
  b.addByte((sofLen >> 8) & 0xFF);
  b.addByte(sofLen & 0xFF);
  b.addByte(8); // sample precision
  b.addByte((height >> 8) & 0xFF);
  b.addByte(height & 0xFF);
  b.addByte((width >> 8) & 0xFF);
  b.addByte(width & 0xFF);
  b.addByte(3); // components
  // Y component
  b.addByte(1); // id
  b.addByte(type == 0 ? 0x21 : 0x22); // H/V: 2x1 for 4:2:2, 2x2 for 4:2:0
  b.addByte(0); // Tq → luma table
  // Cb
  b.addByte(2);
  b.addByte(0x11);
  b.addByte(1);
  // Cr
  b.addByte(3);
  b.addByte(0x11);
  b.addByte(1);
  // DHT — emit all four standard Huffman tables
  _writeDht(b, tc: 0, th: 0, codelens: _lumDcCodelens, symbols: _lumDcSymbols);
  _writeDht(b, tc: 1, th: 0, codelens: _lumAcCodelens, symbols: _lumAcSymbols);
  _writeDht(b, tc: 0, th: 1, codelens: _chmDcCodelens, symbols: _chmDcSymbols);
  _writeDht(b, tc: 1, th: 1, codelens: _chmAcCodelens, symbols: _chmAcSymbols);
  // SOS
  b.addByte(0xFF);
  b.addByte(0xDA);
  const sosLen = 6 + 2 * 3;
  b.addByte((sosLen >> 8) & 0xFF);
  b.addByte(sosLen & 0xFF);
  b.addByte(3); // components in scan
  b.addByte(1); b.addByte(0x00); // Y: DC tbl 0, AC tbl 0
  b.addByte(2); b.addByte(0x11); // Cb: DC tbl 1, AC tbl 1
  b.addByte(3); b.addByte(0x11); // Cr
  b.addByte(0x00); // Ss
  b.addByte(0x3F); // Se
  b.addByte(0x00); // Ah/Al
  // Entropy data
  b.add(entropy);
  // EOI
  b.addByte(0xFF);
  b.addByte(0xD9);
  return b.takeBytes();
}

void _writeDht(
  BytesBuilder b, {
  required int tc, // 0 = DC, 1 = AC
  required int th, // destination
  required List<int> codelens, // 17 bytes: index 0 unused (16 lengths follow)
  required List<int> symbols,
}) {
  // codelens[0] is the per-table-class/dest byte in our literals — RFC 2435
  // Appendix B / JPEG Annex C use a 16-entry BITS array; index 0 is unused
  // and counted in the segment length but never emitted on the wire.
  b.addByte(0xFF);
  b.addByte(0xC4);
  final length = 2 + 1 + 16 + symbols.length;
  b.addByte((length >> 8) & 0xFF);
  b.addByte(length & 0xFF);
  b.addByte((tc << 4) | (th & 0x0F));
  // Skip codelens[0] — it's a JPEG Annex K artifact (the "0" filler that
  // makes the BITS array 17 entries wide instead of 16).
  for (var i = 1; i < 17; i++) {
    b.addByte(codelens[i]);
  }
  for (final s in symbols) {
    b.addByte(s);
  }
}

// ── Opus Packetizer (RFC 7587) ──────────────────────────────────────────────

/// Opus RTP payload packetizer (RFC 7587).
///
/// Opus frames are sent one-per-packet (no fragmentation needed for typical
/// 20ms frames which are well under MTU).
final class OpusPacketizer implements PayloadPacketizer {
  @override
  List<(Uint8List payload, bool marker)> packetize(
    Uint8List encodedData, {
    required bool isKeyFrame,
  }) {
    if (encodedData.isEmpty) return const [];
    // Opus: one frame per RTP packet, marker=true always
    return [(Uint8List.fromList(encodedData), true)];
  }
}

/// Opus RTP payload depacketizer (RFC 7587).
///
/// Each RTP packet contains exactly one Opus frame.
final class OpusDepacketizer implements AudioPayloadDepacketizer {
  @override
  EncodedAudioChunk? depacketize(Uint8List rtpPayload, {
    required int timestamp,
  }) {
    if (rtpPayload.isEmpty) return null;
    return EncodedAudioChunk(
      type: EncodedAudioChunkType.key, // Opus frames are always independently decodable
      timestamp: timestamp,
      data: Uint8List.fromList(rtpPayload),
    );
  }
}
