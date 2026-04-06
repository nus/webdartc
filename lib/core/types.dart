import 'dart:typed_data';

/// A packet to be sent over the network.
final class OutputPacket {
  final Uint8List data;
  final String remoteIp;
  final int remotePort;

  const OutputPacket({
    required this.data,
    required this.remoteIp,
    required this.remotePort,
  });
}

/// A timer token uniquely identifying a scheduled timeout.
sealed class TimerToken {}

final class IceTimerToken extends TimerToken {
  final int id;
  IceTimerToken(this.id);
}

final class DtlsRetransmitToken extends TimerToken {
  final int epoch;
  DtlsRetransmitToken(this.epoch);
}

final class SctpT1InitToken extends TimerToken {
  SctpT1InitToken();
}

final class SctpT1CookieToken extends TimerToken {
  SctpT1CookieToken();
}

final class SctpT3RtxToken extends TimerToken {
  final int tsn;
  SctpT3RtxToken(this.tsn);
}

final class IceKeepaliveToken extends TimerToken {
  IceKeepaliveToken();
}

final class IceGatheringTimeoutToken extends TimerToken {
  IceGatheringTimeoutToken();
}

/// A scheduled timeout event.
final class Timeout {
  final DateTime at;
  final TimerToken token;

  const Timeout({required this.at, required this.token});
}

/// The result of processing a packet or a timeout in a protocol state machine.
final class ProcessResult {
  final List<OutputPacket> outputPackets;
  final Timeout? nextTimeout;

  const ProcessResult({
    this.outputPackets = const [],
    this.nextTimeout,
  });

  static const empty = ProcessResult();
}
