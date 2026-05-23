/// ChannelData framing (RFC 5766 §11.4).
///
/// Once a peer has been bound to a channel number via ChannelBind, data
/// to/from that peer travels through the TURN allocation as 4-byte
/// ChannelData headers + payload (padded to 4-byte boundary on TCP/TLS;
/// padding is optional on UDP but harmless).
///
/// Wire format:
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |         Channel Number        |            Length             |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  /                       Application Data                        /
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Distinguishable from STUN: STUN's first 2 bits are 00; ChannelData's
/// channel-number high 2 bits are 01 (range 0x4000-0x7FFF).
library;

import 'dart:typed_data';

/// Lower bound of the channel-number range valid for application use.
/// Channels 0x0000-0x3FFF are STUN messages (high 2 bits = 00) and
/// 0x8000-0xFFFF are reserved (high 2 bits = 10/11).
const int channelNumberMin = 0x4000;

/// Upper bound of the application channel-number range (inclusive).
const int channelNumberMax = 0x7FFF;

/// Returns true if [n] is a valid TURN application channel number.
bool isValidChannelNumber(int n) =>
    n >= channelNumberMin && n <= channelNumberMax;

/// True when the first byte indicates a ChannelData frame rather than a
/// STUN message. STUN's first 2 bits are 00 (per RFC 5389 §6), so any
/// non-zero high 2 bits indicate non-STUN — and 01 specifically is the
/// ChannelData range.
bool isChannelData(Uint8List raw) {
  if (raw.length < 4) return false;
  return (raw[0] & 0xC0) == 0x40;
}

/// Decoded ChannelData frame.
final class ChannelDataFrame {
  final int channel;
  final Uint8List payload;
  const ChannelDataFrame({required this.channel, required this.payload});
}

/// Build a ChannelData frame. [payload] must fit in 16 bits (65535 bytes).
/// On UDP transport the trailing 4-byte alignment padding is harmless;
/// per RFC 5766 §11.4 it is required on TCP/TLS so callers can pass
/// `pad: true` even on UDP for transport-agnostic builders.
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
  return ChannelDataFrame(
    channel: channel,
    payload: Uint8List.fromList(raw.sublist(4, 4 + length)),
  );
}
