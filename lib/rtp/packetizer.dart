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
