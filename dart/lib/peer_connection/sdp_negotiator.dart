part of 'peer_connection.dart';

/// SDP offer/answer engine for one [PeerConnection]: builds offers and
/// answers, applies local/remote descriptions, owns the ICE credentials
/// (including restart regeneration) and the PT→kind/clock/codec/channels
/// maps derived from the negotiated SDP.
final class SdpNegotiator {
  final PeerConnection _pc;

  SdpNegotiator(this._pc) {
    _regenerateIceCredentials();
  }

  // Local ICE credentials. Mutable: regenerated on an ICE restart
  // (RFC 8445 §9).
  late String _iceUfrag;
  late String _icePwd;
  bool _iceRestartPending = false;
  // Last remote ICE credentials seen — a change in an offer signals a
  // peer-initiated ICE restart.
  String? _remoteIceUfrag;
  String? _remoteIcePwd;

  // SDP — cached parses, so re-negotiation parses each side once and
  // `getStats()` doesn't have to re-tokenise the SDP on every snapshot.
  SessionDescription? _localDescription;
  SessionDescription? _remoteDescription;
  SdpSessionDescription? _localParsed;
  SdpSessionDescription? _remoteParsed;

  /// Parsed remote DTLS fingerprint (algorithm + hex pair) from the
  /// SDP `a=fingerprint` attribute on `setRemoteDescription`. Used in
  /// `getStats` to emit the remote [CertificateStats] entry; null
  /// until the remote description is set.
  ({String algorithm, String hex})? _remoteFp;

  // Dynamic PT→kind / PT→clock-rate / PT→codec maps built from SDP negotiation.
  final Map<int, String> _ptKindMap = {};
  final Map<int, int> _ptClockRateMap = {};
  final Map<int, String> _ptCodecMap = {};
  final Map<int, int> _ptChannelsMap = {};

  /// Generate a fresh ICE ufrag/pwd (RFC 8445 §5.4 lengths). Used at init and
  /// on every ICE restart (local or peer-initiated).
  void _regenerateIceCredentials() {
    _iceUfrag = Csprng.randomHex(4);
    _icePwd = Csprng.randomHex(22);
  }

  // ── PT lookups (populated by setRemoteDescription) ────────────────────────

  /// Audio channel count for [payloadType] from `a=rtpmap` (the optional
  /// third field, e.g. `opus/48000/2`), defaulting to 2 (WebRTC's Opus
  /// default) when unspecified.
  int _channelsForPt(int payloadType) => _ptChannelsMap[payloadType] ?? 2;

  /// RTP clock rate for [payloadType] — from the negotiated `a=rtpmap`,
  /// falling back to the WebRTC defaults (Opus 48 kHz, video 90 kHz) for
  /// static or unmapped PTs.
  int _clockRateForPt(int payloadType, String kind) =>
      _ptClockRateMap[payloadType] ?? (kind == 'audio' ? 48000 : 90000);

  /// Codec key (CodecRegistry lookup key, e.g. `vp8`, `h264`, `opus`) for
  /// [payloadType] from the negotiated `a=rtpmap`, or null if unmapped. The
  /// `a=rtpmap` encoding name (e.g. `VP8`, `H264`, `opus`) is lower-cased to
  /// match the keys CodecRegistry registers under (see [VideoCodecName] /
  /// [AudioCodecName], which are already lower-case).
  String? _codecForPt(int payloadType) => _ptCodecMap[payloadType];

  // RFC 3551 §6: PTs 0–34 are statically assigned to audio codecs.
  static const int _staticAudioPtMax = 34;
  // RFC 3551 §3: PTs 96–127 are the dynamic assignment range.
  static const int _dynamicPtMin = 96;
  static const int _dynamicPtMax = 127;

  String _resolveTrackKind(int payloadType) {
    // Check dynamically negotiated PTs first (populated from SDP).
    final fromSdp = _ptKindMap[payloadType];
    if (fromSdp != null) return fromSdp;
    // Fallback heuristics for well-known static PTs.
    if (payloadType <= _staticAudioPtMax) return 'audio';
    if (payloadType >= _dynamicPtMin && payloadType <= _dynamicPtMax) {
      final kind = _kindOfUnmatchedTransceiver();
      if (kind != null) return kind;
    }
    return 'audio';
  }

  /// Kind of the first transceiver that has no receiver of its kind yet, or
  /// null if every transceiver's kind is already receiving.
  String? _kindOfUnmatchedTransceiver() {
    for (final t in _pc._transceivers) {
      if (!_pc._receivers.values.any((r) => r.kind == t.kind)) return t.kind;
    }
    return null;
  }

  // ── Offer / answer builders ───────────────────────────────────────────────

  Future<SessionDescription> createOffer() async {
    await _pc._ensureTransportStarted();

    // Relay candidates trickle in once the TURN allocation completes,
    // so under relay-only the inline host candidate would be the only
    // non-relay path the offer ever advertised.
    final localIp = _pc._relayOnly ? null : _pc._transport.localAddress;
    final localPort = _pc._relayOnly ? null : _pc._transport.localPort;

    final SdpSessionDescription sdp;
    if (_pc._transceivers.isNotEmpty) {
      // Media session — codec list comes from MediaEngine, optionally
      // narrowed by the transceiver's preferredCodecs.
      final tracks = _pc._transceivers.map((t) {
        final codecs = t.kind == 'audio'
            ? _pc.mediaEngine.resolveAudioCodecs(t.preferredCodecs)
            : _pc.mediaEngine.resolveVideoCodecs(t.preferredCodecs);
        return MediaTrack(
          type: t.kind,
          direction: t.direction.sdpToken,
          senderSsrc: t.sender?.ssrc,
          codecs: codecs,
        );
      }).toList();
      sdp = SdpBuilder.buildMediaSdp(
        ufrag: _iceUfrag,
        password: _icePwd,
        fingerprint: _pc._localCert.sha256Fingerprint,
        isOffer: true,
        tracks: tracks,
        localIp: localIp,
        localPort: localPort,
      );
    } else {
      // Data channel session
      sdp = SdpBuilder.buildDataChannelSdp(
        ufrag: _iceUfrag,
        password: _icePwd,
        fingerprint: _pc._localCert.sha256Fingerprint,
        isOffer: true,
        sctpPort: 5000,
        localIp: localIp,
        localPort: localPort,
      );
    }
    return SessionDescription(type: SessionDescriptionType.offer, sdp: sdp.build());
  }

  Future<SessionDescription> createAnswer() async {
    await _pc._ensureTransportStarted();
    final remoteDesc = _remoteDescription;
    final remoteParsed = _remoteParsed;
    if (remoteDesc == null || remoteParsed == null) {
      throw StateError('createAnswer: no remote offer set');
    }

    final localSenderSsrcs = <String, int>{};
    for (final t in _pc._transceivers) {
      if (t.sender != null) localSenderSsrcs[t.kind] = t.sender!.ssrc;
    }
    // Honour each transceiver's preferredCodecs on the answer side.
    final sdp = SdpBuilder.buildAnswerFromOffer(
      remoteOffer: remoteParsed,
      ufrag: _iceUfrag,
      password: _icePwd,
      fingerprint: _pc._localCert.sha256Fingerprint,
      localIp: _pc._relayOnly ? null : _pc._transport.localAddress,
      localPort: _pc._relayOnly ? null : _pc._transport.localPort,
      localSenderSsrcs: localSenderSsrcs,
      supportedAudioCodecs: _answerCodecNames('audio'),
      supportedVideoCodecs: _answerCodecNames('video'),
    );
    final answerSdp = sdp.build();

    // PT must come from the answer (the codec we narrowed down to), not the
    // offer (which lists every PT the remote was willing to use).
    _assignMidToTransceivers(sdp);

    return SessionDescription(type: SessionDescriptionType.answer, sdp: answerSdp);
  }

  /// Codec names to advertise in the answer for [kind], filtered by the
  /// matching transceiver's preferredCodecs (if any). m-lines without a
  /// local transceiver still negotiate normally, treating the answerer as
  /// recv-only for that kind.
  List<String> _answerCodecNames(String kind) {
    final prefs = _pc._transceivers
        .where((t) => t.kind == kind)
        .firstOrNull
        ?.preferredCodecs;
    final resolved = kind == 'audio'
        ? _pc.mediaEngine.resolveAudioCodecs(prefs)
        : _pc.mediaEngine.resolveVideoCodecs(prefs);
    return [for (final c in resolved) c.name];
  }

  // ── Apply descriptions ────────────────────────────────────────────────────

  Future<void> setLocalDescription(SessionDescription desc) async {
    final parsed = SdpParser.parse(desc.sdp);
    if (parsed.isErr) throw Exception(parsed.error.message);
    _localDescription = desc;
    _localParsed = parsed.value;
    // Applying our own description starts (offer) or finishes (answer) the
    // pending negotiation — clear the W3C negotiation-needed flag.
    _pc._negotiationNeeded = false;
    _pc._setSignalingState(
      desc.type == SessionDescriptionType.offer
          ? SignalingState.haveLocalOffer
          : SignalingState.stable,
    );
    // ICE role: offerer = controlling, answerer = controlled (RFC 8445 §5.1)
    _pc._ice.controlling = desc.type == SessionDescriptionType.offer;
    await _pc._ensureTransportStarted();
    final localParams =
        IceParameters(usernameFragment: _iceUfrag, password: _icePwd);
    final restarting = _iceRestartPending;
    _iceRestartPending = false;
    // On a restart the initiator (offer) drops the peer's stale credentials;
    // the answerer keeps the peer's new credentials it just applied.
    final result = restarting
        ? _pc._ice.restart(localParams,
            hosts: _pc._transport.bindings,
            clearRemote: desc.type == SessionDescriptionType.offer)
        : _pc._ice.startGathering(localParams, hosts: _pc._transport.bindings);
    if (result.isErr) throw Exception(result.error.message);
    // Forward any initial check packets (answerer: remote params already set).
    _pc._transport.handleIceControl(result);
  }

  Future<void> setRemoteDescription(SessionDescription desc) async {
    // Parse first so the description and its parsed cache land
    // atomically — see `setLocalDescription` for the same rationale.
    final parsed = SdpParser.parse(desc.sdp);
    if (parsed.isErr) throw Exception(parsed.error.message);
    final sdp = parsed.value;
    _remoteDescription = desc;
    _remoteParsed = sdp;
    _pc._setSignalingState(
      desc.type == SessionDescriptionType.offer
          ? SignalingState.haveRemoteOffer
          : SignalingState.stable,
    );

    // When we are the offerer and an answer just arrived, apply the
    // negotiated MID/PT to our senders so outgoing RTP uses the remote's
    // expected payload type.
    if (desc.type == SessionDescriptionType.answer) {
      _assignMidToTransceivers(sdp);
    }

    if (sdp.media.isEmpty) return;
    final media = sdp.media.first;

    _ingestPtMaps(sdp);

    // Extract ICE and DTLS parameters (media-level overrides session-level)
    final sa = sdp.sessionAttributes;
    final remoteUfrag = media.iceUfrag ?? sa['ice-ufrag'] ?? '';
    final remotePwd = media.icePwd ?? sa['ice-pwd'] ?? '';

    // A changed ICE ufrag/pwd in an *offer* is a peer-initiated ICE restart
    // (RFC 8445 §9): regenerate our own credentials and flag so the answer
    // carries them and setLocalDescription re-gathers.
    if (desc.type == SessionDescriptionType.offer &&
        _remoteIceUfrag != null &&
        (remoteUfrag != _remoteIceUfrag || remotePwd != _remoteIcePwd)) {
      _regenerateIceCredentials();
      _iceRestartPending = true;
    }
    _remoteIceUfrag = remoteUfrag;
    _remoteIcePwd = remotePwd;

    _ingestRemoteFingerprint(media, sa);

    // Set DTLS role: if remote is active, we are passive (server); otherwise client.
    final setup = media.setup ?? sa['setup'] ?? 'active';
    _pc._dtls.role = (setup == 'active') ? DtlsRole.server : DtlsRole.client;

    // Add remote ICE candidates embedded in SDP (if any).
    for (final cand in media.candidates) {
      _pc._transport.handleIceControl(_pc._ice.addRemoteCandidate(cand));
    }

    _ingestTwccExtensionId(sdp);
    _ingestRemoteSsrcs(sdp);

    // Set remote ICE parameters — starts connectivity checking if local
    // description is already set (both sets of parameters are now known).
    _pc._transport.handleIceControl(_pc._ice.setRemoteParameters(
        IceParameters(usernameFragment: remoteUfrag, password: remotePwd)));
  }

  /// Build PT→kind / clock-rate / codec / channels maps from the remote SDP
  /// for RTP demuxing. Each m-line type (audio/video) lists its payload
  /// types as formats; `a=rtpmap` refines them
  /// (`"<PT> <codec>/<clock>[/<ch>]"`). Clock rate feeds the RFC 3550 §A.8
  /// jitter calc; the codec name (lower-cased to a CodecRegistry key) lets
  /// the receive path build a decoder.
  void _ingestPtMaps(SdpSessionDescription sdp) {
    for (final m in sdp.media) {
      if (m.type == 'application') continue;
      for (final fmt in m.formats) {
        final pt = int.tryParse(fmt);
        if (pt != null) _ptKindMap[pt] = m.type;
      }
      for (final rtpmap in m.getAll('rtpmap')) {
        final space = rtpmap.indexOf(' ');
        if (space < 0) continue;
        final pt = int.tryParse(rtpmap.substring(0, space));
        if (pt == null) continue;
        final parts = rtpmap.substring(space + 1).split('/');
        if (parts[0].isNotEmpty) _ptCodecMap[pt] = parts[0].toLowerCase();
        final rate = parts.length > 1 ? int.tryParse(parts[1]) : null;
        if (rate != null) _ptClockRateMap[pt] = rate;
        final ch = parts.length > 2 ? int.tryParse(parts[2]) : null;
        if (ch != null) _ptChannelsMap[pt] = ch;
      }
    }
  }

  /// Validate and latch the remote `a=fingerprint`, wiring it into the DTLS
  /// layer for certificate verification.
  void _ingestRemoteFingerprint(
      SdpMediaDescription media, Map<String, String> sessionAttrs) {
    final remoteFingerprint = media.fingerprint ?? sessionAttrs['fingerprint'];

    // RFC 8827 §5: a=fingerprint is mandatory in WebRTC offers/answers.
    if (remoteFingerprint == null) {
      throw Exception('Remote SDP missing required a=fingerprint attribute (RFC 8827 §5)');
    }
    // SDP a=fingerprint is "<algorithm> <hex>" (RFC 4572 §5). Split
    // properly so the stats layer can report the actual algorithm the
    // remote used; tolerant fallback treats a missing prefix as
    // sha-256, which is what every real WebRTC peer sends today.
    final spaceIdx = remoteFingerprint.indexOf(' ');
    final algorithm =
        spaceIdx > 0 ? remoteFingerprint.substring(0, spaceIdx) : 'sha-256';
    final hex = spaceIdx > 0
        ? remoteFingerprint.substring(spaceIdx + 1)
        : remoteFingerprint;
    // Reject cryptographically weak fingerprint hashes (RFC 8122 §5:
    // SHA-1 and the MD family are deprecated; RFC 8827 §6.5 mandates
    // SHA-256 for WebRTC). Stronger digests (sha-384/512) are left to
    // pass through — only sha-256 actually verifies against our DTLS
    // layer, but that capability gap is the handshake's concern, not a
    // security one. A weak digest, by contrast, must never be honoured.
    if (const {'sha-1', 'md5', 'md2'}.contains(algorithm.toLowerCase())) {
      throw Exception(
          'Remote a=fingerprint uses weak hash "$algorithm"; '
          'WebRTC requires sha-256 (RFC 8827 §6.5, RFC 8122 §5)');
    }
    _pc._dtls.expectedRemoteFingerprint = hex;
    _remoteFp = (algorithm: algorithm, hex: hex);
  }

  /// Extract the transport-cc extension ID from SDP.
  /// Format: a=extmap:N http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
  void _ingestTwccExtensionId(SdpSessionDescription sdp) {
    for (final m in sdp.media) {
      for (final extmap in m.getAll('extmap')) {
        if (extmap.contains('transport-wide-cc')) {
          final id = int.tryParse(extmap.split(' ').first.split('/').first);
          if (id != null) {
            _pc._rtcp._twccExtId = id;
            if (PeerConnection._debug) {
              webdartcLog('[pc] transport-cc extension ID: $id');
            }
          }
        }
      }
    }
  }

  /// Extract remote SSRCs from SDP for pre-populating RTCP RR.
  void _ingestRemoteSsrcs(SdpSessionDescription sdp) {
    for (final m in sdp.media) {
      for (final ssrcAttr in m.getAll('ssrc')) {
        // Format: "SSRC cname:..." or "SSRC msid:..."
        final spaceIdx = ssrcAttr.indexOf(' ');
        if (spaceIdx > 0) {
          final ssrc = int.tryParse(ssrcAttr.substring(0, spaceIdx));
          if (ssrc != null) {
            _pc._rtcp._rtpRecvStats.putIfAbsent(ssrc, () => _RtpRecvStats(ssrc));
            if (PeerConnection._debug) {
              webdartcLog('[pc] pre-populated remote SSRC from SDP: $ssrc');
            }
          }
        }
      }
    }
  }

  /// Align transceivers to the remote SDP: record each transceiver's MID +
  /// currentDirection, and set its sender's MID, MID header-extension ID (if
  /// negotiated), and negotiated payload type. Runs for both offerer (after
  /// receiving the answer) and answerer (when building the answer).
  void _assignMidToTransceivers(SdpSessionDescription remoteSdp) {
    int midExtId = 0;
    for (final m in remoteSdp.media) {
      for (final extmap in m.getAll('extmap')) {
        if (extmap.contains('sdes:mid')) {
          final id = int.tryParse(extmap.split(' ').first.split('/').first);
          if (id != null) midExtId = id;
        }
      }
    }

    // Pair each m-line with the first unassigned matching-kind sender.
    // Walking transceivers in lockstep with m-lines breaks when the two
    // lists diverge (e.g. offer m=audio+m=video, only video transceiver).
    final assigned = <RtpTransceiver>{};
    for (var i = 0; i < remoteSdp.media.length; i++) {
      final m = remoteSdp.media[i];
      if (m.type == 'application' || m.port == 0) continue;
      final mid = m.mid ?? '$i';
      for (final t in _pc._transceivers) {
        if (t.kind != m.type || assigned.contains(t) || t.stopped) continue;
        // Record the negotiated mid + currentDirection on the transceiver
        // (W3C): currentDirection is the intersection of our preferred
        // direction and the remote m-line's direction.
        t._mid = mid;
        t._currentDirection = RtpTransceiverDirection.negotiated(
            t._direction, RtpTransceiverDirection.fromToken(m.direction));
        // Align the sender (if any) to the negotiated mid + payload type.
        final sender = t.sender;
        if (sender != null) {
          sender._mid = mid;
          sender._midExtId = midExtId;
          if (m.formats.isNotEmpty) {
            final negotiatedPt = int.tryParse(m.formats.first);
            if (negotiatedPt != null) sender.payloadType = negotiatedPt;
          }
          if (PeerConnection._debug) {
            webdartcLog(
                '[pc] sender ${t.kind} mid=$mid extId=$midExtId pt=${sender.payloadType}');
          }
        }
        assigned.add(t);
        break;
      }
    }
  }
}
