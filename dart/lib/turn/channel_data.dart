/// ChannelData framing (RFC 8656 §12.4).
///
/// Distinguishable from STUN by the first 2 bits: STUN = 00, ChannelData
/// = 01 (channel range 0x4000-0x7FFF). Padding to a 4-byte boundary is
/// required on TCP/TLS and optional on UDP.
library;

import 'dart:typed_data';

const int channelNumberMin = 0x4000;
const int channelNumberMax = 0x7FFF;

/// STUN message header length (RFC 8489 §5) — fixed at 20 bytes
/// (type 2 + length 2 + magic cookie 4 + transaction id 12).
const int stunHeaderBytes = 20;

/// Top two bits of the first byte distinguish framing classes on a
/// TURN-TCP stream:
///   * `00` — STUN (`stunHeaderBytes` + body length).
///   * `01` — ChannelData (4-byte header + body, padded to 4-byte
///     multiple on TCP per RFC 8656 §12.5).
/// Anything else means the byte stream is out of sync.
const int _turnTcpClassMask = 0xC0;
const int _turnTcpStunClass = 0x00;
const int _turnTcpChannelDataClass = 0x40;

/// ChannelData header is 4 bytes; bodies on TCP pad to the next 4-byte
/// boundary. The mask is `align - 1` so `(x + mask) & ~mask` rounds up.
const int _channelDataHeaderBytes = 4;
const int _channelDataAlignmentMask = 3;

bool isValidChannelNumber(int n) =>
    n >= channelNumberMin && n <= channelNumberMax;

bool isChannelData(Uint8List raw) {
  if (raw.length < 4) return false;
  return (raw[0] & 0xC0) == 0x40;
}

final class ChannelDataFrame {
  final int channel;
  final Uint8List payload;
  const ChannelDataFrame({required this.channel, required this.payload});
}

/// [pad] forces 4-byte alignment for transport-agnostic builders even on
/// UDP, where the padding is optional per RFC 8656 §12.4.
Uint8List buildChannelData(int channel, Uint8List payload, {bool pad = false}) {
  if (!isValidChannelNumber(channel)) {
    throw ArgumentError('Channel $channel outside [0x4000, 0x7FFF]');
  }
  if (payload.length > 0xFFFF) {
    throw ArgumentError('Payload ${payload.length} bytes exceeds 16-bit length');
  }
  final padded = pad ? ((payload.length + 3) & ~3) : payload.length;
  final out = Uint8List(4 + padded);
  out[0] = (channel >> 8) & 0xFF;
  out[1] = channel & 0xFF;
  out[2] = (payload.length >> 8) & 0xFF;
  out[3] = payload.length & 0xFF;
  out.setRange(4, 4 + payload.length, payload);
  return out;
}

/// Result of inspecting the head of a TURN-over-TCP receive buffer
/// (RFC 8656 §12.5). The wire is a back-to-back stream of STUN messages
/// and ChannelData frames, each with a self-describing length; the
/// receiver peels them off using only the first four bytes plus the
/// declared length.
sealed class TurnTcpFrameLength {
  const TurnTcpFrameLength();
}

/// Buffer is too short to decide; caller should wait for more bytes.
final class TurnTcpFrameLengthNeedMore extends TurnTcpFrameLength {
  const TurnTcpFrameLengthNeedMore();
}

/// Buffer's leading bytes form a complete frame header. [totalBytes] is
/// the total length the frame occupies on the wire (including any
/// 4-byte ChannelData alignment padding); caller still has to wait
/// until the buffer holds at least that many bytes before slicing.
final class TurnTcpFrameLengthKnown extends TurnTcpFrameLength {
  final int totalBytes;
  const TurnTcpFrameLengthKnown(this.totalBytes);
}

/// Leading byte matches neither STUN (`(b0 & 0xC0) == 0x00`) nor
/// ChannelData (`(b0 & 0xC0) == 0x40`) — the stream is out of sync and
/// the only safe action is for the caller to drop the connection.
final class TurnTcpFrameLengthMalformed extends TurnTcpFrameLength {
  const TurnTcpFrameLengthMalformed();
}

/// Decide how many bytes the next complete frame in a TURN-over-TCP
/// byte stream will occupy. Pure; never throws.
TurnTcpFrameLength turnTcpFrameLength(Uint8List buffer) {
  if (buffer.length < _channelDataHeaderBytes) {
    return const TurnTcpFrameLengthNeedMore();
  }
  final framingClass = buffer[0] & _turnTcpClassMask;
  final bodyLen = (buffer[2] << 8) | buffer[3];
  if (framingClass == _turnTcpStunClass) {
    return TurnTcpFrameLengthKnown(stunHeaderBytes + bodyLen);
  }
  if (framingClass == _turnTcpChannelDataClass) {
    return TurnTcpFrameLengthKnown(
        (_channelDataHeaderBytes + bodyLen + _channelDataAlignmentMask) &
            ~_channelDataAlignmentMask);
  }
  return const TurnTcpFrameLengthMalformed();
}

/// Parse a ChannelData frame. Returns null when the input is malformed
/// or the channel number is outside the valid application range.
ChannelDataFrame? parseChannelData(Uint8List raw) {
  if (raw.length < 4) return null;
  final channel = (raw[0] << 8) | raw[1];
  if (!isValidChannelNumber(channel)) return null;
  final length = (raw[2] << 8) | raw[3];
  if (raw.length < 4 + length) return null;
  // `sublist` on a Uint8List already returns a fresh Uint8List; no need
  // to wrap in fromList for a defensive copy.
  return ChannelDataFrame(
    channel: channel,
    payload: raw.sublist(4, 4 + length),
  );
}
