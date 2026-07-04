/// RTP payload packetizer/depacketizer interfaces and implementations.
///
/// Converts between encoded media chunks and RTP-sized payloads.
library;

import 'dart:typed_data';

import '../codec/video_codec.dart';
import '../codec/audio_codec.dart';
import '../crypto/csprng.dart';

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

// ── VP9 Packetizer (draft-ietf-payload-vp9) ─────────────────────────────────

/// VP9 RTP payload format packetizer (draft-ietf-payload-vp9).
///
/// Emits flexible-mode (F=1) payload descriptors with a 15-bit picture ID:
///
///     byte 0: I=1 |  P  | L=0 | F=1 |  B  |  E  | V=0 | Z=0
///     byte 1: M=1 | picture ID high 7 bits
///     byte 2: picture ID low 8 bits
///     [P=1]:  one P_DIFF byte (0x02 — references the previous picture)
///
/// P=0 marks keyframes, B/E mark the first/last fragment of a frame. No
/// scalability structure is sent — decoders read the resolution from the
/// VP9 bitstream itself. The picture ID is stateful: all fragments of one
/// frame share it and it increments once per frame (mod 2^15) — receivers
/// use gaps to detect loss.
final class Vp9Packetizer implements PayloadPacketizer {
  final int maxPayloadSize;

  int _pictureId = Csprng.randomUint32() & 0x7FFF;

  Vp9Packetizer({this.maxPayloadSize = 1200});

  @override
  List<(Uint8List payload, bool marker)> packetize(
    Uint8List encodedData, {
    required bool isKeyFrame,
  }) {
    if (encodedData.isEmpty) return const [];

    final pictureId = _pictureId;
    _pictureId = (_pictureId + 1) & 0x7FFF;

    // 3 descriptor bytes + 1 P_DIFF on delta frames.
    final headerSize = 3 + (isKeyFrame ? 0 : 1);
    final maxChunk = maxPayloadSize - headerSize;
    final results = <(Uint8List, bool)>[];
    var offset = 0;
    var isFirst = true;

    while (offset < encodedData.length) {
      final remaining = encodedData.length - offset;
      final chunkSize = remaining > maxChunk ? maxChunk : remaining;
      final isLast = (offset + chunkSize) >= encodedData.length;

      final payload = Uint8List(headerSize + chunkSize);
      payload[0] = 0x80 | // I: picture ID present
          (isKeyFrame ? 0 : 0x40) | // P: inter-picture predicted
          0x10 | // F: flexible mode
          (isFirst ? 0x08 : 0) | // B: beginning of frame
          (isLast ? 0x04 : 0); // E: end of frame
      payload[1] = 0x80 | (pictureId >> 8); // M=1: 15-bit picture ID
      payload[2] = pictureId & 0xFF;
      if (!isKeyFrame) payload[3] = 0x02; // P_DIFF=1, N=0
      payload.setRange(headerSize, headerSize + chunkSize, encodedData, offset);

      results.add((payload, isLast));
      offset += chunkSize;
      isFirst = false;
    }

    return results;
  }
}

/// VP9 RTP payload format depacketizer (draft-ietf-payload-vp9).
///
/// Parses both flexible-mode (F=1, P_DIFF) and non-flexible-mode (F=0,
/// TL0PICIDX; what Chrome sends) descriptors, including the scalability
/// structure carried on keyframes.
final class Vp9Depacketizer implements VideoPayloadDepacketizer {
  final _fragments = <int>[];
  bool _frameIsKey = false;

  @override
  EncodedVideoChunk? depacketize(Uint8List rtpPayload, {
    required bool marker,
    required int timestamp,
  }) {
    if (rtpPayload.isEmpty) return null;

    final firstByte = rtpPayload[0];
    final hasPictureId = (firstByte & 0x80) != 0; // I
    final interPredicted = (firstByte & 0x40) != 0; // P
    final hasLayerIndices = (firstByte & 0x20) != 0; // L
    final flexibleMode = (firstByte & 0x10) != 0; // F
    final hasSs = (firstByte & 0x02) != 0; // V
    var offset = 1;

    if (hasPictureId) {
      if (offset >= rtpPayload.length) return null;
      final extended = (rtpPayload[offset] & 0x80) != 0; // M: 15-bit
      offset += extended ? 2 : 1;
    }
    if (hasLayerIndices) {
      offset++; // TID/U/SID/D
      if (!flexibleMode) offset++; // TL0PICIDX
    }
    if (flexibleMode && interPredicted) {
      // Up to 3 P_DIFF bytes, chained via the N bit.
      for (var i = 0; i < 3; i++) {
        if (offset >= rtpPayload.length) return null;
        final continues = (rtpPayload[offset++] & 0x01) != 0;
        if (!continues) break;
      }
    }
    if (hasSs) {
      if (offset >= rtpPayload.length) return null;
      final header = rtpPayload[offset++];
      final numSpatialLayers = (header >> 5) + 1; // N_S+1
      if ((header & 0x10) != 0) offset += numSpatialLayers * 4; // Y: dims
      if ((header & 0x08) != 0) {
        // G: picture group descriptions.
        if (offset >= rtpPayload.length) return null;
        final numGroups = rtpPayload[offset++];
        for (var i = 0; i < numGroups; i++) {
          if (offset >= rtpPayload.length) return null;
          final refCount = (rtpPayload[offset++] >> 2) & 0x03; // R
          offset += refCount; // P_DIFFs
        }
      }
    }

    // Empty payload after the descriptor: a padding / bandwidth-probe packet.
    // Chrome sends these with the media SSRC+PT; they must not disturb an
    // in-progress frame.
    if (offset >= rtpPayload.length) return null;

    if (_fragments.isEmpty) _frameIsKey = !interPredicted;
    _fragments.addAll(Uint8List.sublistView(rtpPayload, offset));

    if (!marker) return null; // more fragments coming

    final frameData = Uint8List.fromList(_fragments);
    _fragments.clear();
    final isKey = _frameIsKey;
    _frameIsKey = false;

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

// The per-codec factory lookups (`videoDepacketizerFor` / `videoPacketizerFor`
// / `audioDepacketizerFor`) live in `lib/codec/codec_support.dart`, resolved
// from the declarative CodecDescriptor table so RTP payload support has a
// single source of truth.
