/// ICE candidate (RFC 8445).
final class IceCandidate {
  final String foundation;
  final int componentId; // 1 = RTP, 2 = RTCP (we only use 1)
  final String transport; // "udp"
  final int priority;
  final String ip;
  final int port;
  final IceCandidateType type;
  final String? relatedAddress;
  final int? relatedPort;
  final String? tcpType; // ignored for UDP

  const IceCandidate({
    required this.foundation,
    required this.componentId,
    required this.transport,
    required this.priority,
    required this.ip,
    required this.port,
    required this.type,
    this.relatedAddress,
    this.relatedPort,
    this.tcpType,
  });

  /// Compute priority per RFC 8445 §5.1.2.1.
  ///
  /// priority = (2^24) * type_pref + (2^8) * local_pref + (256 - component_id)
  static int computePriority({
    required int typePreference,
    required int localPreference,
    required int componentId,
  }) {
    return (1 << 24) * typePreference + (1 << 8) * localPreference + (256 - componentId);
  }

  /// Type preferences per RFC 8445.
  static const int typePreferenceHost   = 126;
  static const int typePreferencePrflx  = 110;
  static const int typePreferenceSrflx  = 100;
  static const int typePreferenceRelay  =   0;

  /// Encode as SDP a=candidate line (RFC 8839).
  String toSdpLine() {
    final sb = StringBuffer('candidate:$foundation $componentId $transport $priority $ip $port typ ${type.name}');
    if (relatedAddress != null) {
      sb.write(' raddr $relatedAddress rport $relatedPort');
    }
    return sb.toString();
  }
}

enum IceCandidateType { host, srflx, prflx, relay }

/// ICE session parameters.
final class IceParameters {
  final String usernameFragment; // ufrag
  final String password;

  const IceParameters({required this.usernameFragment, required this.password});
}

/// ICE state.
enum IceState {
  iceNew,
  iceGathering,
  iceGatheringComplete,
  iceChecking,
  iceConnected,
  iceDisconnected,
  iceFailed,
  iceClosed,
}
