import 'dart:typed_data';

import '../core/ip_address.dart';
import '../crypto/hmac_sha1.dart';
import '../crypto/md5.dart';
import 'crc32.dart';
import 'message.dart';

/// STUN message builder (RFC 8489).
abstract final class StunMessageBuilder {
  StunMessageBuilder._();

  /// Serialize [msg] to wire format (no MESSAGE-INTEGRITY or FINGERPRINT).
  static Uint8List build(StunMessage msg) {
    final body = _encodeAttributes(msg.attributes, msg.transactionId);
    return _buildHeader(msg.type, body.length, msg.transactionId, body);
  }

  /// Long-term credential key: MD5(username:realm:password) per
  /// RFC 8489 §14.5. Used as the HMAC-SHA1 key for MESSAGE-INTEGRITY
  /// on TURN messages and any other long-term-authenticated STUN flow.
  /// SASLprep on `username`/`realm` is a no-op for ASCII inputs.
  static Uint8List longTermKey(String username, String realm, String password) {
    return Md5.hash(Uint8List.fromList('$username:$realm:$password'.codeUnits));
  }

  /// Build a message with HMAC-SHA1 MESSAGE-INTEGRITY and (optionally)
  /// FINGERPRINT.
  ///
  /// [key] is the HMAC-SHA1 key — either the raw password (short-term
  /// credential) or [longTermKey] output (long-term credential).
  /// [fingerprint] controls whether a FINGERPRINT attribute is appended;
  /// STUN-over-multiplexed-transport (RFC 8489 §14.7) wants it, plain
  /// TURN-over-its-own-socket doesn't and most TURN servers reject the
  /// connection-id-style FINGERPRINT.
  static Uint8List buildWithIntegrity(StunMessage msg, Uint8List key,
      {bool fingerprint = true}) {
    // Encode all user attributes except integrity/fingerprint
    final userAttrs = msg.attributes
        .where((a) =>
            a.type != StunAttributeType.messageIntegrity &&
            a.type != StunAttributeType.fingerprint)
        .toList();

    final userBody = _encodeAttributes(userAttrs, msg.transactionId);

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
    final bodyWithIntegrity = _encodeAttributes(allAttrs, msg.transactionId);

    if (!fingerprint) {
      return _buildHeader(
          msg.type, bodyWithIntegrity.length, msg.transactionId, bodyWithIntegrity);
    }

    // FINGERPRINT covers header + all attributes up through MESSAGE-INTEGRITY
    // length field includes fingerprint (8 bytes)
    final fpLength = bodyWithIntegrity.length + 8;
    final headerForFp = _buildHeaderBytes(msg.type, fpLength, msg.transactionId);
    final forFp = Uint8List(headerForFp.length + bodyWithIntegrity.length);
    forFp.setRange(0, headerForFp.length, headerForFp);
    forFp.setRange(headerForFp.length, forFp.length, bodyWithIntegrity);

    final crc = Crc32.compute(forFp) ^ 0x5354554E;
    final fpAttr = FingerprintAttr(crc);

    final allWithFp = [...allAttrs, fpAttr];
    final finalBody = _encodeAttributes(allWithFp, msg.transactionId);
    return _buildHeader(msg.type, finalBody.length, msg.transactionId, finalBody);
  }

  /// Verify the MESSAGE-INTEGRITY attribute in the raw STUN packet [raw]
  /// against [key] (the short-term-credential password bytes, or
  /// [longTermKey] output for long-term credentials).
  ///
  /// Returns true iff a MESSAGE-INTEGRITY attribute is present and its
  /// HMAC-SHA1 matches a recomputation over the message up to — but not
  /// including — that attribute, with the header Length field adjusted to
  /// end at the MESSAGE-INTEGRITY attribute per RFC 8489 §14.6. Attributes
  /// after MESSAGE-INTEGRITY (e.g. FINGERPRINT) are excluded from the HMAC,
  /// as the RFC requires. The HMAC covers the literal received bytes, so a
  /// peer that orders or pads attributes differently than [buildWithIntegrity]
  /// still verifies correctly.
  static bool verifyMessageIntegrity(Uint8List raw, Uint8List key) {
    if (raw.length < 20) return false;
    final msgLength = (raw[2] << 8) | raw[3];
    final bodyEnd = 20 + msgLength;
    if (raw.length < bodyEnd) return false;

    var offset = 20;
    while (offset + 4 <= bodyEnd) {
      final attrType = (raw[offset] << 8) | raw[offset + 1];
      final attrLength = (raw[offset + 2] << 8) | raw[offset + 3];
      final valueStart = offset + 4;
      if (valueStart + attrLength > bodyEnd) return false;

      if (attrType == StunAttributeType.messageIntegrity) {
        if (attrLength != 20) return false;
        // The HMAC input is the header (with Length set to end at this
        // attribute = bytes-before-MI + 24) followed by the on-wire bytes
        // before the attribute.
        final bytesBeforeMi = offset - 20;
        final hdr = _buildHeaderBytes(
            (raw[0] << 8) | raw[1], bytesBeforeMi + 24, raw.sublist(8, 20));
        final forHmac = Uint8List(20 + bytesBeforeMi);
        forHmac.setRange(0, 20, hdr);
        forHmac.setRange(20, forHmac.length, raw, 20);
        return HmacSha1.verify(
            key, forHmac, raw.sublist(valueStart, valueStart + 20));
      }

      offset = valueStart + ((attrLength + 3) & ~3);
    }
    return false; // no MESSAGE-INTEGRITY present
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

  static Uint8List _encodeAttributes(
    List<StunAttribute> attrs,
    Uint8List transactionId,
  ) {
    final parts = <Uint8List>[];
    for (final attr in attrs) {
      parts.add(_encodeAttribute(attr, transactionId));
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

  static Uint8List _encodeAttribute(
    StunAttribute attr,
    Uint8List transactionId,
  ) {
    final value = _encodeAttributeValue(attr, transactionId);
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

  static Uint8List _encodeAttributeValue(
    StunAttribute attr,
    Uint8List transactionId,
  ) {
    switch (attr) {
      case XorMappedAddress(:final address, :final port):
        return _encodeAddress(address, port, transactionId);
      case MappedAddress(:final address, :final port):
        return _encodeAddress(address, port, null);
      case UsernameAttr(:final username):
        return Uint8List.fromList(username.codeUnits);
      case MessageIntegrityAttr(:final hmac):
        return Uint8List.fromList(hmac);
      case FingerprintAttr(:final crc32):
        return _uint32Bytes(crc32);
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
      // TURN attributes
      case RealmAttr(:final realm):
        return Uint8List.fromList(realm.codeUnits);
      case NonceAttr(:final nonce):
        return nonce;
      case XorPeerAddress(:final address, :final port):
        return _encodeAddress(address, port, transactionId);
      case XorRelayedAddress(:final address, :final port):
        return _encodeAddress(address, port, transactionId);
      case DataAttr(:final data):
        return data;
      case LifetimeAttr(:final seconds):
        return _uint32Bytes(seconds);
      case RequestedTransportAttr(:final protocol):
        // 1 byte protocol + 3 bytes reserved (RFC 8656 §18.8).
        final out = Uint8List(4);
        out[0] = protocol & 0xFF;
        return out;
      case ChannelNumberAttr(:final channel):
        // 2 bytes channel + 2 bytes reserved (RFC 8656 §18.1).
        final out = Uint8List(4);
        out[0] = (channel >> 8) & 0xFF;
        out[1] = channel & 0xFF;
        return out;
      case DontFragmentAttr():
        return Uint8List(0);
      case RawAttribute(:final value):
        return Uint8List.fromList(value);
    }
  }

  /// Encode a STUN address attribute body. Layout: 1 reserved + 1 family +
  /// 2 port + N address bytes (4 for IPv4, 16 for IPv6). When [xorTxId]
  /// is non-null, port and address are XOR'd per RFC 8489 §14.2 — first
  /// 4 bytes against the magic cookie, remaining 12 (IPv6 only) against
  /// the transaction ID.
  static Uint8List _encodeAddress(
    IpAddress address,
    int port,
    Uint8List? xorTxId,
  ) {
    final addrBytes = address.toBytes();
    final out = Uint8List(4 + addrBytes.length);
    final txPort = xorTxId == null ? port : port ^ (stunMagicCookie >> 16);
    out[0] = 0x00;
    out[1] = address.isV4 ? 0x01 : 0x02;
    out[2] = (txPort >> 8) & 0xFF;
    out[3] = txPort & 0xFF;
    if (xorTxId == null) {
      out.setRange(4, out.length, addrBytes);
    } else {
      out[4] = addrBytes[0] ^ ((stunMagicCookie >> 24) & 0xFF);
      out[5] = addrBytes[1] ^ ((stunMagicCookie >> 16) & 0xFF);
      out[6] = addrBytes[2] ^ ((stunMagicCookie >> 8) & 0xFF);
      out[7] = addrBytes[3] ^ (stunMagicCookie & 0xFF);
      for (var i = 4; i < addrBytes.length; i++) {
        out[4 + i] = addrBytes[i] ^ xorTxId[i - 4];
      }
    }
    return out;
  }

  static Uint8List _uint32Bytes(int v) =>
      Uint8List.fromList([(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]);

  static Uint8List _uint64Bytes(int v) => Uint8List.fromList([
        (v >> 56) & 0xFF, (v >> 48) & 0xFF, (v >> 40) & 0xFF, (v >> 32) & 0xFF,
        (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >>  8) & 0xFF,  v        & 0xFF,
      ]);
}
