import 'dart:typed_data';

/// STUN attribute types (RFC 5389 + RFC 8445).
abstract final class StunAttributeType {
  StunAttributeType._();

  // Comprehension-required (0x0000–0x7FFF)
  static const int mappedAddress    = 0x0001;
  static const int username         = 0x0006;
  static const int messageIntegrity = 0x0008;
  static const int errorCode        = 0x0009;
  static const int unknownAttributes= 0x000A;
  static const int realm            = 0x0014;
  static const int nonce            = 0x0015;
  static const int xorMappedAddress = 0x0020;

  // Comprehension-optional (0x8000–0xFFFF)
  static const int software         = 0x8022;
  static const int alternateServer  = 0x8023;
  static const int fingerprint      = 0x8028;

  // ICE-specific (RFC 8445)
  static const int priority         = 0x0024;
  static const int useCandidate     = 0x0025;
  static const int iceControlled    = 0x8029;
  static const int iceControlling   = 0x802A;
}

/// STUN message types.
abstract final class StunMessageType {
  StunMessageType._();

  static const int bindingRequest              = 0x0001;
  static const int bindingSuccessResponse      = 0x0101;
  static const int bindingErrorResponse        = 0x0111;
  static const int bindingIndication           = 0x0011;
}

/// Magic cookie (RFC 5389 §6).
const int stunMagicCookie = 0x2112A442;

// ── Attribute data classes ────────────────────────────────────────────────────

sealed class StunAttribute {
  final int type;
  const StunAttribute(this.type);
}

final class MappedAddress extends StunAttribute {
  final int family; // 0x01=IPv4, 0x02=IPv6
  final String ip;
  final int port;
  const MappedAddress({required this.ip, required this.port, this.family = 1})
      : super(StunAttributeType.mappedAddress);
}

final class XorMappedAddress extends StunAttribute {
  final String ip;
  final int port;
  const XorMappedAddress({required this.ip, required this.port})
      : super(StunAttributeType.xorMappedAddress);
}

final class UsernameAttr extends StunAttribute {
  final String username;
  const UsernameAttr(this.username) : super(StunAttributeType.username);
}

final class MessageIntegrityAttr extends StunAttribute {
  final Uint8List hmac; // 20 bytes
  const MessageIntegrityAttr(this.hmac) : super(StunAttributeType.messageIntegrity);
}

final class FingerprintAttr extends StunAttribute {
  final int crc32c;
  const FingerprintAttr(this.crc32c) : super(StunAttributeType.fingerprint);
}

final class PriorityAttr extends StunAttribute {
  final int priority;
  const PriorityAttr(this.priority) : super(StunAttributeType.priority);
}

final class UseCandidateAttr extends StunAttribute {
  const UseCandidateAttr() : super(StunAttributeType.useCandidate);
}

final class IceControlledAttr extends StunAttribute {
  final int tieBreaker; // 64-bit, stored as int (Dart's int is 64-bit)
  const IceControlledAttr(this.tieBreaker) : super(StunAttributeType.iceControlled);
}

final class IceControllingAttr extends StunAttribute {
  final int tieBreaker;
  const IceControllingAttr(this.tieBreaker) : super(StunAttributeType.iceControlling);
}

final class ErrorCodeAttr extends StunAttribute {
  final int code;
  final String reason;
  const ErrorCodeAttr({required this.code, required this.reason})
      : super(StunAttributeType.errorCode);
}

final class SoftwareAttr extends StunAttribute {
  final String value;
  const SoftwareAttr(this.value) : super(StunAttributeType.software);
}

final class RawAttribute extends StunAttribute {
  final Uint8List value;
  const RawAttribute(super.type, this.value);
}
