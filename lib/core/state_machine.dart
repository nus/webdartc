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

final class StateError extends ProtocolError {
  @override
  final String message;
  const StateError(this.message);
  @override
  String toString() => 'StateError($message)';
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
  Result<ProcessResult, ProtocolError> processInput(
    Uint8List packet, {
    required String remoteIp,
    required int remotePort,
  });

  /// Handle a previously scheduled timeout.
  Result<ProcessResult, ProtocolError> handleTimeout(TimerToken token);
}
