import 'dart:typed_data';

import '../core/ip_address.dart';

/// STUN attribute types (RFC 5389 + RFC 8445 + RFC 5766 TURN).
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

  // TURN (RFC 5766 / RFC 8656)
  static const int channelNumber       = 0x000C;
  static const int lifetime            = 0x000D;
  static const int xorPeerAddress      = 0x0012;
  static const int data                = 0x0013;
  static const int xorRelayedAddress   = 0x0016;
  static const int requestedTransport  = 0x0019;
  static const int dontFragment        = 0x001A;
}

/// STUN message types (RFC 5389) and TURN extensions (RFC 5766 / RFC 8656).
abstract final class StunMessageType {
  StunMessageType._();

  static const int bindingRequest              = 0x0001;
  static const int bindingSuccessResponse      = 0x0101;
  static const int bindingErrorResponse        = 0x0111;
  static const int bindingIndication           = 0x0011;

  static const int allocateRequest               = 0x0003;
  static const int allocateSuccessResponse       = 0x0103;
  static const int allocateErrorResponse         = 0x0113;
  static const int refreshRequest                = 0x0004;
  static const int refreshSuccessResponse        = 0x0104;
  static const int refreshErrorResponse          = 0x0114;
  static const int sendIndication                = 0x0016;
  static const int dataIndication                = 0x0017;
  static const int createPermissionRequest       = 0x0008;
  static const int createPermissionSuccessResponse = 0x0108;
  static const int createPermissionErrorResponse   = 0x0118;
  static const int channelBindRequest            = 0x0009;
  static const int channelBindSuccessResponse    = 0x0109;
  static const int channelBindErrorResponse      = 0x0119;
}

/// Magic cookie (RFC 5389 §6).
const int stunMagicCookie = 0x2112A442;

// ── Attribute data classes ────────────────────────────────────────────────────

sealed class StunAttribute {
  final int type;
  const StunAttribute(this.type);
}

final class MappedAddress extends StunAttribute {
  final IpAddress address;
  final int port;
  const MappedAddress({required this.address, required this.port})
      : super(StunAttributeType.mappedAddress);

  /// Wire-format family byte (0x01=IPv4, 0x02=IPv6).
  int get family => address.isV4 ? 0x01 : 0x02;
}

final class XorMappedAddress extends StunAttribute {
  final IpAddress address;
  final int port;
  const XorMappedAddress({required this.address, required this.port})
      : super(StunAttributeType.xorMappedAddress);

  /// Wire-format family byte (0x01=IPv4, 0x02=IPv6).
  int get family => address.isV4 ? 0x01 : 0x02;
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

// ── TURN attribute data classes (RFC 5766 / RFC 8656) ────────────────────────

final class RealmAttr extends StunAttribute {
  final String realm;
  const RealmAttr(this.realm) : super(StunAttributeType.realm);
}

final class NonceAttr extends StunAttribute {
  final Uint8List nonce;
  const NonceAttr(this.nonce) : super(StunAttributeType.nonce);
}

final class XorPeerAddress extends StunAttribute {
  final IpAddress address;
  final int port;
  const XorPeerAddress({required this.address, required this.port})
      : super(StunAttributeType.xorPeerAddress);
}

final class XorRelayedAddress extends StunAttribute {
  final IpAddress address;
  final int port;
  const XorRelayedAddress({required this.address, required this.port})
      : super(StunAttributeType.xorRelayedAddress);
}

final class DataAttr extends StunAttribute {
  final Uint8List data;
  const DataAttr(this.data) : super(StunAttributeType.data);
}

final class LifetimeAttr extends StunAttribute {
  final int seconds;
  const LifetimeAttr(this.seconds) : super(StunAttributeType.lifetime);
}

/// IANA Protocol Numbers — 17=UDP, 6=TCP. TURN-UDP carries 17.
final class RequestedTransportAttr extends StunAttribute {
  final int protocol;
  const RequestedTransportAttr(this.protocol)
      : super(StunAttributeType.requestedTransport);
}

/// Channel number (RFC 5766 §11). Valid range 0x4000–0x7FFF; numbers
/// outside that range are reserved or for future use.
final class ChannelNumberAttr extends StunAttribute {
  final int channel;
  const ChannelNumberAttr(this.channel)
      : super(StunAttributeType.channelNumber);
}

final class DontFragmentAttr extends StunAttribute {
  const DontFragmentAttr() : super(StunAttributeType.dontFragment);
}
