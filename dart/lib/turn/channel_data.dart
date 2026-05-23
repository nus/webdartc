/// ChannelData framing (RFC 5766 §11.4).
///
/// Distinguishable from STUN by the first 2 bits: STUN = 00, ChannelData
/// = 01 (channel range 0x4000-0x7FFF). Padding to a 4-byte boundary is
/// required on TCP/TLS and optional on UDP.
library;

import 'dart:typed_data';

const int channelNumberMin = 0x4000;
const int channelNumberMax = 0x7FFF;

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
/// UDP, where the padding is optional per RFC 5766 §11.4.
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
