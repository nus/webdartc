import 'dart:typed_data';

import '../core/result.dart';
import '../core/state_machine.dart' show ParseError;
import 'message.dart';

/// STUN message parser (RFC 5389).
abstract final class StunParser {
  StunParser._();

  /// Returns true if [raw] looks like a STUN message.
  ///
  /// Checks: first two bits are zero, magic cookie present at bytes 4–7.
  static bool isStun(Uint8List raw) {
    if (raw.length < 20) return false;
    if ((raw[0] & 0xC0) != 0) return false;
    final cookie = _readUint32(raw, 4);
    return cookie == stunMagicCookie;
  }

  /// Parse a complete STUN message from [raw].
  static Result<StunMessage, ParseError> parse(Uint8List raw) {
    if (raw.length < 20) {
      return Err(const ParseError('STUN message too short'));
    }
    if ((raw[0] & 0xC0) != 0) {
      return Err(const ParseError('STUN: first two bits must be zero'));
    }
    final cookie = _readUint32(raw, 4);
    if (cookie != stunMagicCookie) {
      return Err(const ParseError('STUN: invalid magic cookie'));
    }

    final messageType = _readUint16(raw, 0);
    final messageLength = _readUint16(raw, 2);
    if (raw.length < 20 + messageLength) {
      return Err(const ParseError('STUN: truncated packet'));
    }

    final transactionId = raw.sublist(8, 20);
    final attributeBytes = raw.sublist(20, 20 + messageLength);

    final attributesResult = _parseAttributes(attributeBytes, raw, transactionId);
    if (attributesResult.isErr) {
      return Err(attributesResult.error);
    }

    return Ok(StunMessage(
      type: messageType,
      transactionId: Uint8List.fromList(transactionId),
      attributes: attributesResult.value,
    ));
  }

  static Result<List<StunAttribute>, ParseError> _parseAttributes(
    Uint8List data,
    Uint8List fullMessage,
    List<int> transactionId,
  ) {
    final attrs = <StunAttribute>[];
    var offset = 0;

    while (offset < data.length) {
      if (offset + 4 > data.length) {
        return Err(const ParseError('STUN: truncated attribute header'));
      }
      final attrType = _readUint16(data, offset);
      final attrLength = _readUint16(data, offset + 2);
      offset += 4;

      if (offset + attrLength > data.length) {
        return Err(const ParseError('STUN: truncated attribute value'));
      }
      final attrValue = data.sublist(offset, offset + attrLength);
      // Padding to 4-byte boundary
      final padded = (attrLength + 3) & ~3;
      offset += padded;

      final attr = _parseAttribute(attrType, attrValue, fullMessage, transactionId);
      if (attr != null) attrs.add(attr);
    }

    return Ok(attrs);
  }

  static StunAttribute? _parseAttribute(
    int type,
    Uint8List value,
    Uint8List fullMessage,
    List<int> transactionId,
  ) {
    switch (type) {
      case StunAttributeType.xorMappedAddress:
        return _parseXorMappedAddress(value, transactionId);
      case StunAttributeType.mappedAddress:
        return _parseMappedAddress(value);
      case StunAttributeType.username:
        return UsernameAttr(String.fromCharCodes(value));
      case StunAttributeType.messageIntegrity:
        if (value.length != 20) return null;
        return MessageIntegrityAttr(Uint8List.fromList(value));
      case StunAttributeType.fingerprint:
        if (value.length != 4) return null;
        return FingerprintAttr(_readUint32(value, 0));
      case StunAttributeType.priority:
        if (value.length != 4) return null;
        return PriorityAttr(_readUint32(value, 0));
      case StunAttributeType.useCandidate:
        return const UseCandidateAttr();
      case StunAttributeType.iceControlled:
        if (value.length != 8) return null;
        return IceControlledAttr(_readUint64(value, 0));
      case StunAttributeType.iceControlling:
        if (value.length != 8) return null;
        return IceControllingAttr(_readUint64(value, 0));
      case StunAttributeType.errorCode:
        return _parseErrorCode(value);
      case StunAttributeType.software:
        return SoftwareAttr(String.fromCharCodes(value));
      default:
        return RawAttribute(type, Uint8List.fromList(value));
    }
  }

  static XorMappedAddress? _parseXorMappedAddress(
    Uint8List value,
    List<int> transactionId,
  ) {
    if (value.length < 8) return null;
    final family = value[1];
    final xPort = _readUint16(value, 2);
    final port = xPort ^ (stunMagicCookie >> 16);

    if (family == 0x01) {
      // IPv4
      final xAddr = _readUint32(value, 4);
      final addr = xAddr ^ stunMagicCookie;
      final ip =
          '${(addr >> 24) & 0xFF}.${(addr >> 16) & 0xFF}.${(addr >> 8) & 0xFF}.${addr & 0xFF}';
      return XorMappedAddress(ip: ip, port: port);
    }
    // IPv6 not implemented — return raw
    return null;
  }

  static MappedAddress? _parseMappedAddress(Uint8List value) {
    if (value.length < 8) return null;
    final family = value[1];
    final port = _readUint16(value, 2);
    if (family == 0x01) {
      final addr = _readUint32(value, 4);
      final ip =
          '${(addr >> 24) & 0xFF}.${(addr >> 16) & 0xFF}.${(addr >> 8) & 0xFF}.${addr & 0xFF}';
      return MappedAddress(ip: ip, port: port);
    }
    return null;
  }

  static ErrorCodeAttr? _parseErrorCode(Uint8List value) {
    if (value.length < 4) return null;
    final clazz = value[2] & 0x07;
    final number = value[3];
    final code = clazz * 100 + number;
    final reason = String.fromCharCodes(value.sublist(4));
    return ErrorCodeAttr(code: code, reason: reason);
  }

  static int _readUint16(Uint8List data, int offset) =>
      (data[offset] << 8) | data[offset + 1];

  static int _readUint32(Uint8List data, int offset) =>
      ((data[offset] << 24) |
       (data[offset + 1] << 16) |
       (data[offset + 2] << 8) |
        data[offset + 3]) >>>
      0;

  static int _readUint64(Uint8List data, int offset) {
    final hi = _readUint32(data, offset);
    final lo = _readUint32(data, offset + 4);
    return (hi << 32) | lo;
  }
}
