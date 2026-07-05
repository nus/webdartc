import 'dart:typed_data';

import 'result.dart';
import 'types.dart';

export 'result.dart';
export 'types.dart';

/// Protocol-level errors.
sealed class ProtocolError {
  const ProtocolError();
  String get message;
}

final class ParseError extends ProtocolError {
  @override
  final String message;
  const ParseError(this.message);
  @override
  String toString() => 'ParseError($message)';
}

final class ProtocolStateError extends ProtocolError {
  @override
  final String message;
  const ProtocolStateError(this.message);
  @override
  String toString() => 'ProtocolStateError($message)';
}

final class CryptoError extends ProtocolError {
  @override
  final String message;
  const CryptoError(this.message);
  @override
  String toString() => 'CryptoError($message)';
}

final class InternalError extends ProtocolError {
  @override
  final String message;
  const InternalError(this.message);
  @override
  String toString() => 'InternalError($message)';
}

/// A pure protocol state machine with no I/O.
///
/// All network interaction is expressed as [ProcessResult] values containing
/// [OutputPacket] lists. Timers are expressed as [Timeout] values to be
/// scheduled by [TransportController].
abstract interface class ProtocolStateMachine {
  /// Process an incoming UDP packet.
  ///
  /// [localIp] is the address of the local socket the packet arrived on, when
  /// the caller knows it. ICE uses it to identify the receiving host
  /// candidate; other state machines may ignore it.
  Result<ProcessResult, ProtocolError> processInput(
    Uint8List packet, {
    required IpAddress remoteIp,
    required int remotePort,
    IpAddress? localIp,
  });

  /// Handle a previously scheduled timeout.
  Result<ProcessResult, ProtocolError> handleTimeout(TimerToken token);
}
