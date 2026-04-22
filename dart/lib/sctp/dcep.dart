import 'dart:typed_data';

/// DCEP (Data Channel Establishment Protocol) message types (RFC 8832).
abstract final class DcepMessageType {
  DcepMessageType._();
  static const int dataChannelOpen  = 0x03;
  static const int dataChannelAck   = 0x02;
}

/// DCEP channel types.
enum DcepChannelType {
  reliable(0x00),
  reliableUnordered(0x80),
  partialReliableRexmit(0x01),
  partialReliableRexmitUnordered(0x81),
  partialReliableTimed(0x02),
  partialReliableTimedUnordered(0x82);

  final int value;
  const DcepChannelType(this.value);

  static DcepChannelType fromValue(int v) =>
      DcepChannelType.values.firstWhere((e) => e.value == v,
          orElse: () => DcepChannelType.reliable);
}

/// DCEP DATA_CHANNEL_OPEN message (RFC 8832 §5.1).
final class DcepOpenMessage {
  static const int ppid = 50; // WebRTC DCEP PPID

  final DcepChannelType channelType;
  final int priority;
  final int reliabilityParameter;
  final String label;
  final String protocol;

  const DcepOpenMessage({
    required this.channelType,
    this.priority = 0,
    this.reliabilityParameter = 0,
    required this.label,
    this.protocol = '',
  });

  Uint8List encode() {
    final labelBytes = label.codeUnits;
    final protocolBytes = protocol.codeUnits;
    final body = Uint8List(12 + labelBytes.length + protocolBytes.length);
    body[0] = DcepMessageType.dataChannelOpen;
    body[1] = channelType.value;
    body[2] = (priority >> 8) & 0xFF;
    body[3] = priority & 0xFF;
    body[4] = (reliabilityParameter >> 24) & 0xFF;
    body[5] = (reliabilityParameter >> 16) & 0xFF;
    body[6] = (reliabilityParameter >>  8) & 0xFF;
    body[7] = reliabilityParameter & 0xFF;
    body[8] = (labelBytes.length >> 8) & 0xFF;
    body[9] = labelBytes.length & 0xFF;
    body[10] = (protocolBytes.length >> 8) & 0xFF;
    body[11] = protocolBytes.length & 0xFF;
    body.setRange(12, 12 + labelBytes.length, labelBytes);
    body.setRange(12 + labelBytes.length, body.length, protocolBytes);
    return body;
  }

  static DcepOpenMessage? parse(Uint8List data) {
    if (data.length < 12) return null;
    if (data[0] != DcepMessageType.dataChannelOpen) return null;
    final channelType = DcepChannelType.fromValue(data[1]);
    final priority = (data[2] << 8) | data[3];
    final reliabilityParam =
        ((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]) >>> 0;
    final labelLen    = (data[8] << 8) | data[9];
    final protocolLen = (data[10] << 8) | data[11];
    if (data.length < 12 + labelLen + protocolLen) return null;
    final label    = String.fromCharCodes(data.sublist(12, 12 + labelLen));
    final protocol = String.fromCharCodes(
        data.sublist(12 + labelLen, 12 + labelLen + protocolLen));
    return DcepOpenMessage(
      channelType: channelType,
      priority: priority,
      reliabilityParameter: reliabilityParam,
      label: label,
      protocol: protocol,
    );
  }
}

/// DCEP DATA_CHANNEL_ACK message (RFC 8832 §5.2).
final class DcepAckMessage {
  static final Uint8List encoded = Uint8List.fromList([DcepMessageType.dataChannelAck]);

  static bool isDcepAck(Uint8List data) =>
      data.isNotEmpty && data[0] == DcepMessageType.dataChannelAck;
}

/// PPID values for SCTP DATA chunks (RFC 8831).
abstract final class SctpPpid {
  SctpPpid._();
  static const int webrtcDcep     = 50;
  static const int webrtcString   = 51;
  static const int webrtcBinary   = 53;
  static const int webrtcStringEmpty  = 56;
  static const int webrtcBinaryEmpty  = 57;
}
