import 'dart:typed_data';

import 'ip_address.dart';

export 'ip_address.dart';

/// A bound UDP endpoint: bind address plus the port the socket landed
/// on (for `port = 0` the kernel picks per-socket).
typedef HostBinding = ({IpAddress ip, int port});

/// A packet to be sent over the network.
///
/// [remoteIp] is the destination IP literal or hostname; hostnames are
/// resolved lazily by [TransportController] (used for STUN/TURN URIs).
/// [localIp] selects the source socket — null means "any", which is
/// fine for client-initiated traffic; ICE binding responses set it
/// explicitly so the reply leaves on the interface that received the
/// request.
final class OutputPacket {
  final Uint8List data;
  final String remoteIp;
  final int remotePort;
  final IpAddress? localIp;

  const OutputPacket({
    required this.data,
    required this.remoteIp,
    required this.remotePort,
    this.localIp,
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

/// Fires the periodic STUN consent-freshness check on the selected pair
/// (RFC 7675 §5.1) — also serves as the keepalive (§6).
final class IceConsentToken extends TimerToken {
  IceConsentToken();
}

final class IceGatheringTimeoutToken extends TimerToken {
  IceGatheringTimeoutToken();
}

final class TurnRefreshToken extends TimerToken {
  TurnRefreshToken();
}

final class TurnPermissionRefreshToken extends TimerToken {
  final IpAddress peerIp;
  TurnPermissionRefreshToken(this.peerIp);
}

final class TurnChannelRefreshToken extends TimerToken {
  final int channel;
  TurnChannelRefreshToken(this.channel);
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
