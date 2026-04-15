import 'dart:typed_data';

import 'attributes.dart';

export 'attributes.dart';

/// A STUN message (RFC 5389 §6).
final class StunMessage {
  /// Message type (e.g. [StunMessageType.bindingRequest]).
  final int type;

  /// 96-bit transaction ID.
  final Uint8List transactionId; // 12 bytes

  /// Attributes in order.
  final List<StunAttribute> attributes;

  StunMessage({
    required this.type,
    required this.transactionId,
    this.attributes = const [],
  }) : assert(transactionId.length == 12, 'Transaction ID must be 12 bytes');

  bool get isRequest => (type & 0x0110) == 0x0000;
  bool get isSuccessResponse => (type & 0x0110) == 0x0100;
  bool get isErrorResponse => (type & 0x0110) == 0x0110;
  bool get isIndication => (type & 0x0110) == 0x0010;

  /// First attribute of type [T], or null.
  T? attribute<T extends StunAttribute>() {
    for (final a in attributes) {
      if (a is T) return a;
    }
    return null;
  }
}
