import '../ice/candidate.dart';

/// SDP session description (RFC 8866).
final class SdpSessionDescription {
  final String? origin;
  final String? sessionName;
  final List<SdpMediaDescription> media;
  final Map<String, String> sessionAttributes;

  const SdpSessionDescription({
    this.origin,
    this.sessionName,
    this.media = const [],
    this.sessionAttributes = const {},
  });

  /// Serialize to SDP string.
  String build() {
    final sb = StringBuffer();
    sb.writeln('v=0');
    sb.writeln(origin ?? 'o=- 0 0 IN IP4 0.0.0.0');
    sb.writeln('s=${sessionName ?? '-'}');
    sb.writeln('t=0 0');
    for (final entry in sessionAttributes.entries) {
      sb.writeln('a=${entry.key}:${entry.value}');
    }
    for (final m in media) {
      sb.write(m.build());
    }
    return sb.toString();
  }
}

/// SDP media description (RFC 8866 §5.14).
final class SdpMediaDescription {
  final String type; // "audio", "video", "application"
  final int port;
  final String proto; // "UDP/DTLS/SCTP", "RTP/SAVPF", etc.
  final List<String> formats;
  final Map<String, String> attributes;
  /// All attributes as ordered pairs (preserves duplicates like rtpmap, rtcp-fb).
  final List<(String, String)> allAttributes;
  final List<String> rawAttributes;
  final List<IceCandidate> candidates;

  const SdpMediaDescription({
    required this.type,
    required this.port,
    required this.proto,
    required this.formats,
    this.attributes = const {},
    this.allAttributes = const [],
    this.rawAttributes = const [],
    this.candidates = const [],
  });

  String? get iceUfrag => attributes['ice-ufrag'];
  String? get icePwd   => attributes['ice-pwd'];
  String? get fingerprint => attributes['fingerprint'];
  String? get setup    => attributes['setup'];
  String? get mid      => attributes['mid'];
  String? get sctpPort => attributes['sctp-port'];

  /// Get the direction attribute (sendrecv, recvonly, sendonly, inactive).
  String get direction {
    for (final key in ['sendrecv', 'recvonly', 'sendonly', 'inactive']) {
      if (attributes.containsKey(key)) return key;
    }
    return 'sendrecv';
  }

  /// Get all values for a given attribute key (e.g. 'rtpmap', 'rtcp-fb').
  List<String> getAll(String key) =>
      allAttributes.where((a) => a.$1 == key).map((a) => a.$2).toList();

  /// Index `a=fmtp:<pt> <params>` lines by payload type. Allocates a
  /// fresh map each call (intentionally a method, not a getter, so
  /// callers can see the cost) — hoist when reading inside a loop.
  /// Lines that don't parse as `<int> <params>` are silently dropped
  /// (best-effort against malformed remote SDPs).
  Map<int, String> fmtpByPayloadType() {
    final out = <int, String>{};
    for (final f in getAll('fmtp')) {
      final space = f.indexOf(' ');
      if (space <= 0) continue;
      final pt = int.tryParse(f.substring(0, space));
      if (pt == null) continue;
      out[pt] = f.substring(space + 1);
    }
    return out;
  }

  String build() {
    final sb = StringBuffer();
    sb.writeln('m=$type $port $proto ${formats.join(' ')}');
    sb.writeln('c=IN IP4 0.0.0.0');
    for (final entry in attributes.entries) {
      if (entry.value.isEmpty) {
        sb.writeln('a=${entry.key}');
      } else {
        sb.writeln('a=${entry.key}:${entry.value}');
      }
    }
    for (final raw in rawAttributes) {
      sb.writeln('a=$raw');
    }
    for (final c in candidates) {
      sb.writeln('a=${c.toSdpLine()}');
    }
    return sb.toString();
  }
}

/// ICE candidate init (from SDP a=candidate line).
final class IceCandidateInit {
  final String candidate;
  final String sdpMid;
  final int sdpMLineIndex;

  const IceCandidateInit({
    required this.candidate,
    required this.sdpMid,
    required this.sdpMLineIndex,
  });
}
