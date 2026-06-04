import '../core/ip_address.dart';
import '../core/result.dart';
import '../core/state_machine.dart' show ParseError;
import '../ice/candidate.dart';
import 'session_description.dart';

export 'session_description.dart';

/// SDP parser (RFC 8866 + RFC 8829 JSEP + RFC 9143 BUNDLE).
abstract final class SdpParser {
  SdpParser._();

  /// Parse a complete SDP session description.
  static Result<SdpSessionDescription, ParseError> parse(String sdpText) {
    final lines = sdpText.split(RegExp(r'\r?\n'));
    final sessionAttrs = <String, String>{};
    final mediaDescriptions = <SdpMediaDescription>[];
    String? origin;
    String? sessionName;

    SdpMediaDescription? currentMedia;
    Map<String, String>? currentAttrs;
    List<(String, String)>? currentAllAttrs;
    List<IceCandidate> currentCandidates = [];

    void flushMedia() {
      if (currentMedia != null) {
        mediaDescriptions.add(SdpMediaDescription(
          type: currentMedia!.type,
          port: currentMedia!.port,
          proto: currentMedia!.proto,
          formats: currentMedia!.formats,
          attributes: Map.unmodifiable(currentAttrs ?? {}),
          allAttributes: List.unmodifiable(currentAllAttrs ?? []),
          candidates: List.unmodifiable(currentCandidates),
        ));
        currentMedia = null;
        currentAttrs = null;
        currentAllAttrs = null;
        currentCandidates = [];
      }
    }

    for (final line in lines) {
      if (line.isEmpty) continue;
      if (line.length < 2 || line[1] != '=') continue;

      final type = line[0];
      final value = line.substring(2);

      if (currentMedia == null) {
        // Session level
        switch (type) {
          case 'o':
            origin = 'o=$value';
          case 's':
            sessionName = value;
          case 'a':
            final kv = _parseAttr(value);
            sessionAttrs[kv.$1] = kv.$2;
          case 'm':
            flushMedia();
            currentMedia = _parseMediaLine(value);
            currentAttrs = {};
            currentAllAttrs = [];
            currentCandidates = [];
        }
      } else {
        switch (type) {
          case 'm':
            flushMedia();
            currentMedia = _parseMediaLine(value);
            currentAttrs = {};
            currentAllAttrs = [];
            currentCandidates = [];
          case 'a':
            final kv = _parseAttr(value);
            if (kv.$1 == 'candidate') {
              final cand = _parseCandidate(kv.$2);
              if (cand != null) currentCandidates.add(cand);
            } else {
              currentAttrs![kv.$1] = kv.$2;
              currentAllAttrs!.add(kv);
            }
        }
      }
    }
    flushMedia();

    return Ok(SdpSessionDescription(
      origin: origin,
      sessionName: sessionName,
      media: mediaDescriptions,
      sessionAttributes: sessionAttrs,
    ));
  }

  /// Parse a single `a=candidate:...` attribute value.
  static Result<IceCandidateInit, ParseError> parseCandidate(String line) {
    final cand = _parseCandidate(line);
    if (cand == null) return Err(const ParseError('SDP: invalid candidate line'));
    return Ok(IceCandidateInit(candidate: line, sdpMid: '', sdpMLineIndex: 0));
  }

  /// Parse an ICE candidate from SDP attribute value (RFC 8839 §5.1).
  static IceCandidate? parseCandidateToIce(String line) =>
      _parseCandidate(line);

  // ── Private helpers ───────────────────────────────────────────────────────

  static SdpMediaDescription _parseMediaLine(String value) {
    // m=<type> <port> <proto> <fmt list>
    final parts = value.split(' ');
    if (parts.length < 4) {
      return SdpMediaDescription(
        type: parts.isNotEmpty ? parts[0] : 'application',
        port: 9,
        proto: parts.length > 2 ? parts[2] : 'UDP/DTLS/SCTP',
        formats: [],
      );
    }
    final port = int.tryParse(parts[1]) ?? 9;
    final formats = parts.sublist(3);
    return SdpMediaDescription(
      type: parts[0],
      port: port,
      proto: parts[2],
      formats: formats,
    );
  }

  static (String, String) _parseAttr(String value) {
    final idx = value.indexOf(':');
    if (idx < 0) return (value, '');
    return (value.substring(0, idx), value.substring(idx + 1));
  }

  /// Parse `candidate:foundation componentId transport priority ip port typ type [extensions]`
  static IceCandidate? _parseCandidate(String value) {
    // Strip leading "candidate:" if present
    final s = value.startsWith('candidate:') ? value.substring(10) : value;
    final parts = s.split(' ');
    if (parts.length < 8) return null;

    final foundation = parts[0];
    final componentId = int.tryParse(parts[1]) ?? 1;
    final transport = parts[2].toLowerCase();
    final priority = int.tryParse(parts[3]) ?? 0;
    final ip = IpAddress.tryParse(parts[4]);
    if (ip == null) return null;
    final port = int.tryParse(parts[5]) ?? 0;
    // parts[6] == "typ"
    final typeStr = parts.length > 7 ? parts[7] : 'host';
    final type = IceCandidateType.values.firstWhere(
      (t) => t.name == typeStr,
      orElse: () => IceCandidateType.host,
    );

    IpAddress? relatedAddress;
    int? relatedPort;
    for (var i = 8; i + 1 < parts.length; i += 2) {
      if (parts[i] == 'raddr') relatedAddress = IpAddress.tryParse(parts[i + 1]);
      if (parts[i] == 'rport') relatedPort = int.tryParse(parts[i + 1]);
    }

    return IceCandidate(
      foundation: foundation,
      componentId: componentId,
      transport: transport,
      priority: priority,
      ip: ip,
      port: port,
      type: type,
      relatedAddress: relatedAddress,
      relatedPort: relatedPort,
    );
  }
}

/// SDP builder for JSEP offers and answers (RFC 8829).
abstract final class SdpBuilder {
  SdpBuilder._();

  /// Build an SDP offer/answer for a data channel session. Pass `null`
  /// for [localIp]/[localPort] to skip the inline host candidate (used
  /// when `IceTransportPolicy.relay` is in effect — relay candidates
  /// trickle in later from TURN allocations).
  static SdpSessionDescription buildDataChannelSdp({
    required String ufrag,
    required String password,
    required String fingerprint, // SHA-256 colon-separated
    required bool isOffer,
    required int sctpPort,
    String? localIp,
    int? localPort,
    String mid = '0',
  }) {
    final setup = isOffer ? 'actpass' : 'active';
    final attrs = <String, String>{
      'mid': mid,
      'ice-ufrag': ufrag,
      'ice-pwd': password,
      'ice-options': 'trickle',
      'fingerprint': 'sha-256 $fingerprint',
      'setup': setup,
      'sctp-port': '$sctpPort',
      'max-message-size': '262144',
    };

    final candidates = <IceCandidate>[];
    if (localIp != null && localPort != null) {
      candidates.add(_hostCandidate(IpAddress.parse(localIp), localPort));
    }

    final media = SdpMediaDescription(
      type: 'application',
      port: 9,
      proto: 'UDP/DTLS/SCTP',
      formats: ['webrtc-datachannel'],
      attributes: attrs,
      candidates: candidates,
    );

    return SdpSessionDescription(
      origin: 'o=- ${DateTime.now().millisecondsSinceEpoch} 2 IN IP4 127.0.0.1',
      sessionName: '-',
      media: [media],
      sessionAttributes: {
        'group': 'BUNDLE $mid',
        'extmap-allow-mixed': '',
        'msid-semantic': ' WMS',
      },
    );
  }

  /// Build an SDP offer/answer for an audio/video session.
  static SdpSessionDescription buildMediaSdp({
    required String ufrag,
    required String password,
    required String fingerprint,
    required bool isOffer,
    required List<MediaTrack> tracks,
    String? localIp,
    int? localPort,
    String mid = '0',
  }) {
    final setup = isOffer ? 'actpass' : 'active';
    final mediaDescriptions = <SdpMediaDescription>[];

    for (var i = 0; i < tracks.length; i++) {
      final track = tracks[i];
      final trackMid = i == 0 ? mid : '$i';
      final attrs = <String, String>{
        'mid': trackMid,
        'ice-ufrag': ufrag,
        'ice-pwd': password,
        'ice-options': 'trickle',
        'fingerprint': 'sha-256 $fingerprint',
        'setup': setup,
        track.direction: '',
        'rtcp-mux': '',
      };

      // Build rtpmap / fmtp as rawAttributes (multiple lines allowed)
      final rawAttrs = <String>[];
      for (final codec in track.codecs) {
        final ch = codec.channels != null ? '/${codec.channels}' : '';
        rawAttrs.add('rtpmap:${codec.payloadType} ${codec.name}/${codec.clockRate}$ch');
        if (codec.fmtpParams != null) {
          rawAttrs.add('fmtp:${codec.payloadType} ${codec.fmtpParams}');
        }
        for (final fb in codec.rtcpFb) {
          rawAttrs.add('rtcp-fb:${codec.payloadType} $fb');
        }
      }

      // Signal sender SSRC for BUNDLE demux (RFC 5576). Chrome requires
      // either signaled SSRC or MID RTP header extension; without one,
      // incoming RTP is silently dropped.
      if (track.senderSsrc != null &&
          (track.direction == 'sendonly' ||
              track.direction == 'sendrecv')) {
        final ssrc = track.senderSsrc!;
        rawAttrs.add('ssrc:$ssrc cname:webdartc');
        rawAttrs.add('ssrc:$ssrc msid:webdartc-stream webdartc-track-$i');
      }

      final candidates = (localIp != null && localPort != null)
          ? [_hostCandidate(IpAddress.parse(localIp), localPort)]
          : const <IceCandidate>[];

      mediaDescriptions.add(SdpMediaDescription(
        type: track.type,
        port: 9,
        proto: 'UDP/TLS/RTP/SAVPF',
        formats: track.codecs.map((c) => '${c.payloadType}').toList(),
        attributes: attrs,
        rawAttributes: rawAttrs,
        candidates: candidates,
      ));
    }

    return SdpSessionDescription(
      origin: 'o=- ${DateTime.now().millisecondsSinceEpoch} 2 IN IP4 127.0.0.1',
      sessionName: '-',
      media: mediaDescriptions,
      sessionAttributes: {
        'group': 'BUNDLE ${tracks.asMap().keys.map((i) => i == 0 ? mid : '$i').join(' ')}',
        'extmap-allow-mixed': '',
        'msid-semantic': ' WMS',
      },
    );
  }

  /// Build an SDP answer from a remote offer (RFC 3264 Offer/Answer).
  ///
  /// Selects codecs from the offer that we support, reverses direction,
  /// and preserves mids/BUNDLE from the offer.
  static SdpSessionDescription buildAnswerFromOffer({
    required SdpSessionDescription remoteOffer,
    required String ufrag,
    required String password,
    required String fingerprint,
    String? localIp,
    int? localPort,
    List<String> supportedAudioCodecs = const ['opus'],
    List<String> supportedVideoCodecs = const ['VP8', 'VP9', 'H264'],
    Map<String, int> localSenderSsrcs = const {}, // kind → SSRC
  }) {
    final hostCandidates = (localIp != null && localPort != null)
        ? [_hostCandidate(IpAddress.parse(localIp), localPort)]
        : const <IceCandidate>[];
    final mediaDescriptions = <SdpMediaDescription>[];
    final mids = <String>[];

    for (final rm in remoteOffer.media) {
      final remoteMid = rm.mid ?? '${mediaDescriptions.length}';
      mids.add(remoteMid);

      if (rm.type == 'application') {
        // Data channel — accept as-is
        final attrs = <String, String>{
          'mid': remoteMid,
          'ice-ufrag': ufrag,
          'ice-pwd': password,
          'ice-options': 'trickle',
          'fingerprint': 'sha-256 $fingerprint',
          'setup': _answerSetup(rm, remoteOffer),
          'sctp-port': rm.sctpPort ?? '5000',
          'max-message-size': '262144',
        };
        mediaDescriptions.add(SdpMediaDescription(
          type: 'application',
          port: 9,
          proto: rm.proto,
          formats: rm.formats,
          attributes: attrs,
          candidates: hostCandidates,
        ));
      } else {
        // Audio or video — select supported codecs from offer
        final supported = rm.type == 'audio'
            ? supportedAudioCodecs
            : supportedVideoCodecs;

        // Parse rtpmap lines from the offer to find matching codecs
        final rtpmaps = rm.getAll('rtpmap');
        final selectedFormats = <String>[];
        final rawAttrs = <String>[];

        final fmtpByPt = rm.fmtpByPayloadType();
        for (final rtpmap in rtpmaps) {
          // rtpmap value: "PT codec/clockRate[/channels]"
          final spaceIdx = rtpmap.indexOf(' ');
          if (spaceIdx < 0) continue;
          final pt = rtpmap.substring(0, spaceIdx);
          final codecInfo = rtpmap.substring(spaceIdx + 1);
          final codecName = codecInfo.split('/').first;

          // Case-insensitive match, canonical write-back: `supported`
          // carries the IANA-canonical spelling (`'VP8'`, `'opus'`)
          // from MediaEngine, so a non-conforming offer like `vp8` is
          // answered with `VP8`. Matches libwebrtc / Pion / aiortc /
          // Firefox behaviour. The `isNotEmpty` gate doubles as a
          // codecName-empty filter (malformed rtpmap "PT /...") since
          // an empty needle can't match any non-empty `supported`
          // entry.
          final canonical = supported.firstWhere(
            (s) => s.toLowerCase() == codecName.toLowerCase(),
            orElse: () => '',
          );
          if (canonical.isNotEmpty) {
            selectedFormats.add(pt);
            final tail = codecInfo.substring(codecName.length);
            rawAttrs.add('rtpmap:$pt $canonical$tail');
            final ptInt = int.tryParse(pt);
            final fmtp = ptInt == null ? null : fmtpByPt[ptInt];
            if (fmtp != null) rawAttrs.add('fmtp:$pt $fmtp');
            // Copy rtcp-fb for this PT (including transport-cc).
            for (final fb in rm.getAll('rtcp-fb')) {
              if (fb.startsWith('$pt ')) {
                rawAttrs.add('rtcp-fb:$fb');
              }
            }
          }
        }

        // Copy extmap lines from offer (including transport-wide-cc).
        for (final extmap in rm.getAll('extmap')) {
          rawAttrs.add('extmap:$extmap');
        }

        if (selectedFormats.isEmpty) {
          // Reject this m-line (port=0)
          mediaDescriptions.add(SdpMediaDescription(
            type: rm.type,
            port: 0,
            proto: rm.proto,
            formats: rm.formats,
          ));
          continue;
        }

        // Reverse direction; then downgrade if we have no sender for this
        // kind. Telling the remote `sendrecv` while we never produce RTP
        // confuses Chrome enough to stop routing its own media over the
        // same BUNDLE.
        var answerDir = _reverseDirection(rm.direction);
        final hasLocalSender = localSenderSsrcs.containsKey(rm.type);
        if (!hasLocalSender) {
          if (answerDir == 'sendrecv') {
            answerDir = 'recvonly';
          } else if (answerDir == 'sendonly') {
            answerDir = 'inactive';
          }
        }

        final attrs = <String, String>{
          'mid': remoteMid,
          'ice-ufrag': ufrag,
          'ice-pwd': password,
          'ice-options': 'trickle',
          'fingerprint': 'sha-256 $fingerprint',
          'setup': _answerSetup(rm, remoteOffer),
          answerDir: '',
          'rtcp-mux': '',
        };

        final ssrc = localSenderSsrcs[rm.type];
        if (ssrc != null) {
          final mediaIdx = mediaDescriptions.length;
          rawAttrs.add('ssrc:$ssrc cname:webdartc');
          rawAttrs.add('ssrc:$ssrc msid:webdartc-stream webdartc-track-$mediaIdx');
        }

        mediaDescriptions.add(SdpMediaDescription(
          type: rm.type,
          port: 9,
          proto: rm.proto,
          formats: selectedFormats,
          attributes: attrs,
          allAttributes: _allAttrsFrom(attrs, rawAttrs),
          rawAttributes: rawAttrs,
          candidates: hostCandidates,
        ));
      }
    }

    // Mirror the BUNDLE group from the offer
    final bundleGroup = mids.join(' ');
    return SdpSessionDescription(
      origin: 'o=- ${DateTime.now().millisecondsSinceEpoch} 2 IN IP4 127.0.0.1',
      sessionName: '-',
      media: mediaDescriptions,
      sessionAttributes: {
        'group': 'BUNDLE $bundleGroup',
        'extmap-allow-mixed': '',
        'msid-semantic': ' WMS',
      },
    );
  }

  /// Mirror what SdpParser would produce when round-tripping
  /// `attrs` + `rawAttrs` through `build()` and back: every entry shows up
  /// in `allAttributes` so callers can use `getAll(key)`.
  static List<(String, String)> _allAttrsFrom(
      Map<String, String> attrs, List<String> rawAttrs) {
    final out = <(String, String)>[];
    for (final e in attrs.entries) {
      out.add((e.key, e.value));
    }
    for (final r in rawAttrs) {
      final i = r.indexOf(':');
      out.add(i < 0 ? (r, '') : (r.substring(0, i), r.substring(i + 1)));
    }
    return out;
  }

  static String _reverseDirection(String dir) {
    switch (dir) {
      case 'sendonly': return 'recvonly';
      case 'recvonly': return 'sendonly';
      case 'inactive': return 'inactive';
      default: return 'sendrecv';
    }
  }

  /// Answer-side DTLS role (RFC 5763 §5). The answerer must pick the
  /// opposite role to an offerer that committed to one: `active` offer →
  /// `passive` answer; an `actpass` (or absent / `passive`) offer lets us
  /// be the client, so we answer `active`. This must stay consistent with
  /// the `DtlsRole` chosen in PeerConnection.setRemoteDescription.
  static String _answerSetup(
      SdpMediaDescription offerMedia, SdpSessionDescription offer) {
    final offerSetup =
        offerMedia.setup ?? offer.sessionAttributes['setup'] ?? 'actpass';
    return offerSetup == 'active' ? 'passive' : 'active';
  }

  static IceCandidate _hostCandidate(IpAddress ip, int port) => IceCandidate(
    foundation: '1',
    componentId: 1,
    transport: 'udp',
    priority: IceCandidate.computePriority(
      typePreference: IceCandidate.typePreferenceHost,
      localPreference: 65535,
      componentId: 1,
    ),
    ip: ip,
    port: port,
    type: IceCandidateType.host,
  );
}

final class MediaTrack {
  final String type;
  final List<RtpCodec> codecs;
  final String direction;

  /// Sender SSRC for this m-line (when we send). When non-null, the offer
  /// emits `a=ssrc:NNN cname:...` so the remote can demultiplex bundled RTP
  /// (required by modern Chrome without MID header extension).
  final int? senderSsrc;

  const MediaTrack({
    required this.type,
    required this.codecs,
    this.direction = 'sendrecv',
    this.senderSsrc,
  });
}

final class RtpCodec {
  final int payloadType;
  final String name;
  final int clockRate;
  final int? channels;
  final String? fmtpParams;
  final List<String> rtcpFb;
  const RtpCodec({
    required this.payloadType,
    required this.name,
    required this.clockRate,
    this.channels,
    this.fmtpParams,
    this.rtcpFb = const [],
  });
}
