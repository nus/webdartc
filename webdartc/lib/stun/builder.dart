import 'dart:typed_data';

import '../crypto/hmac_sha1.dart';
import 'crc32c.dart';
import 'message.dart';

/// STUN message builder (RFC 5389).
abstract final class StunMessageBuilder {
  StunMessageBuilder._();

  /// Serialize [msg] to wire format (no MESSAGE-INTEGRITY or FINGERPRINT).
  static Uint8List build(StunMessage msg) {
    final body = _encodeAttributes(msg.attributes);
    return _buildHeader(msg.type, body.length, msg.transactionId, body);
  }

  /// Build a message with HMAC-SHA1 MESSAGE-INTEGRITY and FINGERPRINT.
  ///
  /// [key] is the HMAC-SHA1 key (password in short-term credential).
  static Uint8List buildWithIntegrity(StunMessage msg, Uint8List key) {
    // Encode all user attributes except integrity/fingerprint
    final userAttrs = msg.attributes
        .where((a) =>
            a.type != StunAttributeType.messageIntegrity &&
            a.type != StunAttributeType.fingerprint)
        .toList();

    final userBody = _encodeAttributes(userAttrs);

    // The HMAC covers the header + attributes up through (but not including)
    // MESSAGE-INTEGRITY. The length field in the header for HMAC purposes
    // includes the MESSAGE-INTEGRITY attribute (24 bytes).
    final hmacLength = userBody.length + 24; // +4 type/len +20 hmac value
    final headerForHmac = _buildHeaderBytes(msg.type, hmacLength, msg.transactionId);
    final forHmac = Uint8List(headerForHmac.length + userBody.length);
    forHmac.setRange(0, headerForHmac.length, headerForHmac);
    forHmac.setRange(headerForHmac.length, forHmac.length, userBody);

    final hmac = HmacSha1.compute(key, forHmac);
    final integrityAttr = MessageIntegrityAttr(hmac);

    // Build with integrity included
    final allAttrs = [...userAttrs, integrityAttr];
    final bodyWithIntegrity = _encodeAttributes(allAttrs);

    // FINGERPRINT covers header + all attributes up through MESSAGE-INTEGRITY
    // length field includes fingerprint (8 bytes)
    final fpLength = bodyWithIntegrity.length + 8;
    final headerForFp = _buildHeaderBytes(msg.type, fpLength, msg.transactionId);
    final forFp = Uint8List(headerForFp.length + bodyWithIntegrity.length);
    forFp.setRange(0, headerForFp.length, headerForFp);
    forFp.setRange(headerForFp.length, forFp.length, bodyWithIntegrity);

    final crc = Crc32c.compute(forFp) ^ 0x5354554E;
    final fpAttr = FingerprintAttr(crc);

    final allWithFp = [...allAttrs, fpAttr];
    final finalBody = _encodeAttributes(allWithFp);
    return _buildHeader(msg.type, finalBody.length, msg.transactionId, finalBody);
  }

  static Uint8List _buildHeader(
      int type, int bodyLength, Uint8List txId, Uint8List body) {
    final header = _buildHeaderBytes(type, bodyLength, txId);
    final out = Uint8List(header.length + body.length);
    out.setRange(0, header.length, header);
    out.setRange(header.length, out.length, body);
    return out;
  }

  static Uint8List _buildHeaderBytes(int type, int length, Uint8List txId) {
    final header = Uint8List(20);
    header[0] = (type >> 8) & 0xFF;
    header[1] = type & 0xFF;
    header[2] = (length >> 8) & 0xFF;
    header[3] = length & 0xFF;
    // Magic cookie
    header[4] = 0x21;
    header[5] = 0x12;
    header[6] = 0xA4;
    header[7] = 0x42;
    header.setRange(8, 20, txId);
    return header;
  }

  static Uint8List _encodeAttributes(List<StunAttribute> attrs) {
    final parts = <Uint8List>[];
    for (final attr in attrs) {
      parts.add(_encodeAttribute(attr));
    }
    final total = parts.fold(0, (s, p) => s + p.length);
    final out = Uint8List(total);
    var offset = 0;
    for (final p in parts) {
      out.setRange(offset, offset + p.length, p);
      offset += p.length;
    }
    return out;
  }

  static Uint8List _encodeAttribute(StunAttribute attr) {
    final value = _encodeAttributeValue(attr);
    final padded = (value.length + 3) & ~3;
    final out = Uint8List(4 + padded);
    out[0] = (attr.type >> 8) & 0xFF;
    out[1] = attr.type & 0xFF;
    out[2] = (value.length >> 8) & 0xFF;
    out[3] = value.length & 0xFF;
    out.setRange(4, 4 + value.length, value);
    // Padding bytes are zero (already)
    return out;
  }

  static Uint8List _encodeAttributeValue(StunAttribute attr) {
    switch (attr) {
      case XorMappedAddress(:final ip, :final port):
        return _encodeXorMappedAddress(ip, port);
      case MappedAddress(:final ip, :final port, :final family):
        return _encodeMappedAddress(ip, port, family);
      case UsernameAttr(:final username):
        return Uint8List.fromList(username.codeUnits);
      case MessageIntegrityAttr(:final hmac):
        return Uint8List.fromList(hmac);
      case FingerprintAttr(:final crc32c):
        return _uint32Bytes(crc32c);
      case PriorityAttr(:final priority):
        return _uint32Bytes(priority);
      case UseCandidateAttr():
        return Uint8List(0);
      case IceControlledAttr(:final tieBreaker):
        return _uint64Bytes(tieBreaker);
      case IceControllingAttr(:final tieBreaker):
        return _uint64Bytes(tieBreaker);
      case ErrorCodeAttr(:final code, :final reason):
        final clazz = code ~/ 100;
        final number = code % 100;
        final reasonBytes = reason.codeUnits;
        final out = Uint8List(4 + reasonBytes.length);
        out[2] = clazz & 0x07;
        out[3] = number & 0xFF;
        out.setRange(4, out.length, reasonBytes);
        return out;
      case SoftwareAttr(:final value):
        return Uint8List.fromList(value.codeUnits);
      case RawAttribute(:final value):
        return Uint8List.fromList(value);
    }
  }

  static Uint8List _encodeXorMappedAddress(String ip, int port) {
    final xPort = port ^ (stunMagicCookie >> 16);
    final parts = ip.split('.').map(int.parse).toList();
    final addrInt = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    final xAddr = addrInt ^ stunMagicCookie;
    return Uint8List.fromList([
      0x00, 0x01,
      (xPort >> 8) & 0xFF, xPort & 0xFF,
      (xAddr >> 24) & 0xFF, (xAddr >> 16) & 0xFF, (xAddr >> 8) & 0xFF, xAddr & 0xFF,
    ]);
  }

  static Uint8List _encodeMappedAddress(String ip, int port, int family) {
    final parts = ip.split('.').map(int.parse).toList();
    final addrInt = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    return Uint8List.fromList([
      0x00, family & 0xFF,
      (port >> 8) & 0xFF, port & 0xFF,
      (addrInt >> 24) & 0xFF, (addrInt >> 16) & 0xFF, (addrInt >> 8) & 0xFF, addrInt & 0xFF,
    ]);
  }

  static Uint8List _uint32Bytes(int v) =>
      Uint8List.fromList([(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]);

  static Uint8List _uint64Bytes(int v) => Uint8List.fromList([
        (v >> 56) & 0xFF, (v >> 48) & 0xFF, (v >> 40) & 0xFF, (v >> 32) & 0xFF,
        (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >>  8) & 0xFF,  v        & 0xFF,
      ]);
}
