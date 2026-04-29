import 'dart:async';
import 'dart:io' show Platform, stderr;
import 'dart:typed_data';

import '../crypto/csprng.dart';
import '../crypto/ecdsa.dart';
import '../dtls/state_machine.dart';
import '../ice/state_machine.dart';
import '../media/media_stream.dart';
import '../media/media_stream_track.dart';
import '../rtp/parser.dart';
import '../rtp/rtp_transport.dart';
import '../sctp/state_machine.dart';
import '../sdp/parser.dart';
import '../srtp/context.dart';
import '../transport/transport_controller.dart';

part 'data_channel.dart';
part 'events.dart';

/// ICE server configuration.
final class IceServer {
  final List<String> urls;
  final String? username;
  final String? credential;

  const IceServer({required this.urls, this.username, this.credential});
}

/// PeerConnection configuration.
final class PeerConnectionConfiguration {
  final List<IceServer> iceServers;
  final IceCandidateType? iceTransportPolicy;
  final String bundlePolicy; // "balanced" | "max-bundle" | "max-compat"
  final String rtcpMuxPolicy;

  const PeerConnectionConfiguration({
    this.iceServers = const [],
    this.iceTransportPolicy,
    this.bundlePolicy = 'max-bundle',
    this.rtcpMuxPolicy = 'require',
  });
}

/// Session description (offer/answer/pranswer/rollback).
final class SessionDescription {
  final SessionDescriptionType type;
  final String sdp;

  const SessionDescription({required this.type, required this.sdp});
}

enum SessionDescriptionType { offer, pranswer, answer, rollback }

/// Returns the default [RtpCodec] for a given video codec name, or null if
/// the library does not have a built-in entry for it.
RtpCodec? _videoCodecByName(String name) {
  switch (name.toUpperCase()) {
    case 'VP8':
      return const RtpCodec(
        payloadType: 96,
        name: 'VP8',
        clockRate: 90000,
        rtcpFb: ['nack', 'nack pli', 'ccm fir', 'goog-remb'],
      );
    case 'H264':
      // Constrained Baseline 3.1 — maximum Chrome/Firefox interop.
      return const RtpCodec(
        payloadType: 102,
        name: 'H264',
        clockRate: 90000,
        fmtpParams:
            'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f',
        rtcpFb: ['nack', 'nack pli', 'ccm fir', 'goog-remb'],
      );
    default:
      return null;
  }
}

/// WebRTC PeerConnection (W3C API without "RTC" prefix).
///
/// Maps to W3C RTCPeerConnection.
/// Deprecated W3C APIs are not implemented.
final class PeerConnection {
  final PeerConnectionConfiguration configuration;

  // State
  SignalingState _signalingState = SignalingState.stable;
  IceConnectionState _iceConnectionState = IceConnectionState.iceNew;
  PeerConnectionState _connectionState = PeerConnectionState.connecting;

  // Protocol modules
  final _transport = TransportController();
  late final IceStateMachine _ice;
  late final DtlsStateMachine _dtls;
  late final SctpStateMachine _sctp;
  SrtpContext? _srtp;

  // Local credentials
  late final EcdsaCertificate _localCert;
  late final String _iceUfrag;
  late final String _icePwd;

  // SDP
  SessionDescription? _localDescription;
  SessionDescription? _remoteDescription;

  // Data channels
  final Map<int, DataChannel> _dataChannels = {};
  int _nextDataChannelId = 0; // even for offerer, odd for answerer

  // Media transceivers
  final List<_MediaTransceiver> _transceivers = [];
  final Map<int, RtpReceiver> _receivers = {}; // SSRC → receiver

  // RTP reception stats for RTCP RR
  final Map<int, _RtpRecvStats> _rtpRecvStats = {};
  int _localRtcpSsrc = 0; // Our SSRC for RTCP reports
  Timer? _rtcpTimer;
  final Set<int> _pendingPliSsrcs = {}; // SSRCs needing PLI in next RTCP

  // Transport-CC state
  int _twccExtId = 0; // extension ID from SDP (0 = not negotiated)
  final List<_TwccEntry> _twccRecvLog = [];
  int _twccFbCount = 0;

  // Stream controllers
  final _iceCandidateController =
      StreamController<PeerConnectionIceEvent>.broadcast();
  final _dataChannelController =
      StreamController<DataChannelEvent>.broadcast();
  final _trackController = StreamController<TrackEvent>.broadcast();
  final _rtpPacketController = StreamController<RtpPacket>.broadcast();
  final _iceStateController = StreamController<IceConnectionState>.broadcast();
  final _connectionStateController =
      StreamController<PeerConnectionState>.broadcast();
  final _signalingStateController =
      StreamController<SignalingState>.broadcast();

  PeerConnection({required this.configuration}) {
    _init();
  }

  // ── State properties ──────────────────────────────────────────────────────

  SignalingState get signalingState => _signalingState;
  IceConnectionState get iceConnectionState => _iceConnectionState;
  PeerConnectionState get connectionState => _connectionState;
  SessionDescription? get localDescription => _localDescription;
  SessionDescription? get remoteDescription => _remoteDescription;

  // ── Event streams ─────────────────────────────────────────────────────────

  Stream<PeerConnectionIceEvent> get onIceCandidate =>
      _iceCandidateController.stream;
  Stream<DataChannelEvent> get onDataChannel => _dataChannelController.stream;
  Stream<TrackEvent> get onTrack => _trackController.stream;
  /// Stream of received RTP packets (parsed, after SRTP decryption).
  Stream<RtpPacket> get onRtpPacket => _rtpPacketController.stream;

  Stream<IceConnectionState> get onIceConnectionStateChange =>
      _iceStateController.stream;
  Stream<PeerConnectionState> get onConnectionStateChange =>
      _connectionStateController.stream;
  Stream<SignalingState> get onSignalingStateChange =>
      _signalingStateController.stream;

  // ── W3C API ───────────────────────────────────────────────────────────────

  /// Create an SDP offer.
  Future<SessionDescription> createOffer() async {
    if (_signalingState != SignalingState.stable &&
        _signalingState != SignalingState.haveLocalOffer) {
      throw StateError('createOffer: invalid state $_signalingState');
    }
    await _ensureTransportStarted();

    final SdpSessionDescription sdp;
    if (_transceivers.isNotEmpty) {
      // Media session
      final tracks = _transceivers.map((t) {
        if (t.kind == 'audio') {
          return MediaTrack(
            type: 'audio',
            direction: t.direction,
            senderSsrc: t.sender?.ssrc,
            codecs: [
              const RtpCodec(payloadType: 111, name: 'opus', clockRate: 48000, channels: 2,
                  fmtpParams: 'minptime=10;useinbandfec=1'),
            ],
          );
        } else {
          final names = t.preferredCodecs ?? const ['VP8'];
          final codecs = names
              .map(_videoCodecByName)
              .whereType<RtpCodec>()
              .toList();
          return MediaTrack(
            type: 'video',
            direction: t.direction,
            senderSsrc: t.sender?.ssrc,
            codecs: codecs,
          );
        }
      }).toList();
      sdp = SdpBuilder.buildMediaSdp(
        ufrag: _iceUfrag,
        password: _icePwd,
        fingerprint: _localCert.sha256Fingerprint,
        isOffer: true,
        tracks: tracks,
        localIp: _transport.localAddress,
        localPort: _transport.localPort,
      );
    } else {
      // Data channel session
      sdp = SdpBuilder.buildDataChannelSdp(
        ufrag: _iceUfrag,
        password: _icePwd,
        fingerprint: _localCert.sha256Fingerprint,
        isOffer: true,
        sctpPort: 5000,
        localIp: _transport.localAddress,
        localPort: _transport.localPort,
      );
    }
    return SessionDescription(type: SessionDescriptionType.offer, sdp: sdp.build());
  }

  /// Create an SDP answer based on the remote offer (RFC 3264).
  Future<SessionDescription> createAnswer() async {
    if (_signalingState != SignalingState.haveRemoteOffer) {
      throw StateError('createAnswer: invalid state $_signalingState');
    }
    await _ensureTransportStarted();
    final remoteDesc = _remoteDescription;
    if (remoteDesc == null) {
      throw StateError('createAnswer: no remote offer set');
    }
    final parsed = SdpParser.parse(remoteDesc.sdp);
    if (parsed.isErr) throw Exception(parsed.error.message);

    final localSenderSsrcs = <String, int>{};
    for (final t in _transceivers) {
      if (t.sender != null) localSenderSsrcs[t.kind] = t.sender!.ssrc;
    }
    final sdp = SdpBuilder.buildAnswerFromOffer(
      remoteOffer: parsed.value,
      ufrag: _iceUfrag,
      password: _icePwd,
      fingerprint: _localCert.sha256Fingerprint,
      localIp: _transport.localAddress,
      localPort: _transport.localPort,
      localSenderSsrcs: localSenderSsrcs,
    );
    final answerSdp = sdp.build();

    // Assign MID + extmap ID to senders for BUNDLE demux (RFC 8843).
    _assignMidToSenders(parsed.value);

    return SessionDescription(type: SessionDescriptionType.answer, sdp: answerSdp);
  }

  /// Set the local description and begin ICE gathering.
  Future<void> setLocalDescription(SessionDescription desc) async {
    _localDescription = desc;
    _setSignalingState(
      desc.type == SessionDescriptionType.offer
          ? SignalingState.haveLocalOffer
          : SignalingState.stable,
    );
    // ICE role: offerer = controlling, answerer = controlled (RFC 8445 §5.1)
    _ice.controlling = desc.type == SessionDescriptionType.offer;
    await _ensureTransportStarted();
    final result = _ice.startGathering(
      IceParameters(usernameFragment: _iceUfrag, password: _icePwd),
      localIp: _transport.localAddress,
      localPort: _transport.localPort,
    );
    if (result.isErr) throw Exception(result.error.message);
    // Forward any initial check packets (answerer: remote params already set).
    _transport.handleIceControl(result);
  }

  /// Set the remote description.
  Future<void> setRemoteDescription(SessionDescription desc) async {
    _remoteDescription = desc;
    _setSignalingState(
      desc.type == SessionDescriptionType.offer
          ? SignalingState.haveRemoteOffer
          : SignalingState.stable,
    );

    final parsed = SdpParser.parse(desc.sdp);
    if (parsed.isErr) throw Exception(parsed.error.message);
    final sdp = parsed.value;

    // When we are the offerer and an answer just arrived, apply the
    // negotiated MID/PT to our senders so outgoing RTP uses the remote's
    // expected payload type.
    if (desc.type == SessionDescriptionType.answer) {
      _assignMidToSenders(sdp);
    }

    if (sdp.media.isEmpty) return;
    final media = sdp.media.first;

    // Build PT→kind map from remote SDP for RTP demuxing.
    // Each m-line type (audio/video) lists its payload types as formats.
    for (final m in sdp.media) {
      if (m.type == 'application') continue;
      for (final fmt in m.formats) {
        final pt = int.tryParse(fmt);
        if (pt != null) _ptKindMap[pt] = m.type;
      }
    }

    // Extract ICE and DTLS parameters (media-level overrides session-level)
    final sa = sdp.sessionAttributes;
    final remoteUfrag = media.iceUfrag ?? sa['ice-ufrag'] ?? '';
    final remotePwd = media.icePwd ?? sa['ice-pwd'] ?? '';
    final remoteFingerprint = media.fingerprint ?? sa['fingerprint'];
    final setup = media.setup ?? sa['setup'] ?? 'active';

    // RFC 8827 §5: a=fingerprint is mandatory in WebRTC offers/answers.
    if (remoteFingerprint == null) {
      throw Exception('Remote SDP missing required a=fingerprint attribute (RFC 8827 §5)');
    }
    // Strip "sha-256 " prefix if present
    _dtls.expectedRemoteFingerprint = remoteFingerprint.startsWith('sha-256 ')
        ? remoteFingerprint.substring(8)
        : remoteFingerprint;

    // Set DTLS role: if remote is active, we are passive (server); otherwise client.
    _dtls.role = (setup == 'active') ? DtlsRole.server : DtlsRole.client;

    // Add remote ICE candidates embedded in SDP (if any).
    for (final cand in media.candidates) {
      _transport.handleIceControl(_ice.addRemoteCandidate(cand));
    }

    // Extract transport-cc extension ID from SDP.
    // Format: a=extmap:N http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
    for (final m in sdp.media) {
      for (final extmap in m.getAll('extmap')) {
        if (extmap.contains('transport-wide-cc')) {
          final id = int.tryParse(extmap.split(' ').first.split('/').first);
          if (id != null) {
            _twccExtId = id;
            if (_debug) _log('[pc] transport-cc extension ID: $id');
          }
        }
      }
    }

    // Extract remote SSRCs from SDP for pre-populating RTCP RR.
    for (final m in sdp.media) {
      for (final ssrcAttr in m.getAll('ssrc')) {
        // Format: "SSRC cname:..." or "SSRC msid:..."
        final spaceIdx = ssrcAttr.indexOf(' ');
        if (spaceIdx > 0) {
          final ssrc = int.tryParse(ssrcAttr.substring(0, spaceIdx));
          if (ssrc != null) {
            _rtpRecvStats.putIfAbsent(ssrc, () => _RtpRecvStats(ssrc));
            if (_debug) _log('[pc] pre-populated remote SSRC from SDP: $ssrc');
          }
        }
      }
    }

    // Set remote ICE parameters — starts connectivity checking if local
    // description is already set (both sets of parameters are now known).
    _transport.handleIceControl(_ice.setRemoteParameters(
        IceParameters(usernameFragment: remoteUfrag, password: remotePwd)));
  }

  /// Add a remote ICE candidate (Trickle ICE).
  Future<void> addIceCandidate(IceCandidateInit candidate) async {
    final ice = SdpParser.parseCandidateToIce(candidate.candidate);
    if (ice != null) _transport.handleIceControl(_ice.addRemoteCandidate(ice));
  }

  /// Create a data channel.
  DataChannel createDataChannel(String label, [DataChannelInit? init]) {
    final opts = init ?? const DataChannelInit();
    final id = opts.id ?? _allocateDataChannelId();
    final channel = DataChannel(
      label: label,
      ordered: opts.ordered,
      maxRetransmitTime: opts.maxPacketLifeTime,
      maxRetransmits: opts.maxRetransmits,
      protocol: opts.protocol,
      negotiated: opts.negotiated,
      id: id,
    );
    channel._sendCallback = (Uint8List data, {bool binary = true}) {
      final ppid = binary ? SctpPpid.webrtcBinary : SctpPpid.webrtcString;
      final result = _sctp.sendData(
        data: data,
        streamId: id,
        ordered: opts.ordered,
        ppid: ppid,
      );
      if (result.isOk) {
        for (final pkt in result.value.outputPackets) {
          _transport.sendSctp(pkt.data);
        }
      }
    };
    _dataChannels[id] = channel;

    // Send DCEP OPEN when SCTP is established
    _onSctpEstablished(() {
      final result = _sctp.openDataChannel(
        label: label,
        ordered: opts.ordered,
        streamId: id,
      );
      if (result.isOk) {
        for (final pkt in result.value.outputPackets) {
          _transport.sendSctp(pkt.data);
        }
      }
    });

    return channel;
  }

  /// Add a media transceiver (audio or video).
  ///
  /// [preferredCodecs] is an ordered list of codec names (e.g. `['H264', 'VP8']`)
  /// to offer, in preference order. If null, a library default is used.
  void addTransceiver(String kind, {
    String direction = 'sendrecv',
    List<String>? preferredCodecs,
  }) {
    final t = _MediaTransceiver(
      kind: kind, direction: direction, preferredCodecs: preferredCodecs);
    // Create sender if direction includes sending
    if (direction == 'sendrecv' || direction == 'sendonly') {
      final pt = kind == 'audio' ? 111 : 96;
      final clockRate = kind == 'audio' ? 48000 : 90000;
      t.sender = RtpSender._(
        kind: kind,
        ssrc: Csprng.randomUint32(),
        payloadType: pt,
        clockRate: clockRate,
      );
      t.sender!._sendCallback = _sendSrtpRtp;
    }
    _transceivers.add(t);
  }

  /// W3C: Add a MediaStreamTrack to the connection.
  ///
  /// Creates a transceiver for the track's kind and attaches the track to the sender.
  RtpSender addTrack(MediaStreamTrack track, [List<MediaStream>? streams]) {
    addTransceiver(track.kind, direction: 'sendrecv');
    final sender = _transceivers.last.sender!;
    sender._track = track;
    return sender;
  }

  /// Get all RTP senders (for sending media).
  List<RtpSender> getSenders() =>
      _transceivers.where((t) => t.sender != null).map((t) => t.sender!).toList();

  /// Align senders to the remote SDP: set MID, MID header-extension ID (if
  /// negotiated), and the negotiated payload type. Runs for both offerer
  /// (after receiving the answer) and answerer (when building the answer).
  void _assignMidToSenders(SdpSessionDescription remoteSdp) {
    int midExtId = 0;
    for (final m in remoteSdp.media) {
      for (final extmap in m.getAll('extmap')) {
        if (extmap.contains('sdes:mid')) {
          final id = int.tryParse(extmap.split(' ').first.split('/').first);
          if (id != null) midExtId = id;
        }
      }
    }

    int tIdx = 0;
    for (final m in remoteSdp.media) {
      if (m.type == 'application') continue;
      final mid = m.mid ?? '${remoteSdp.media.indexOf(m)}';
      while (tIdx < _transceivers.length && _transceivers[tIdx].kind != m.type) {
        tIdx++;
      }
      if (tIdx < _transceivers.length && _transceivers[tIdx].sender != null) {
        final sender = _transceivers[tIdx].sender!;
        sender._mid = mid;
        sender._midExtId = midExtId;
        // Update sender PT to match the negotiated codec. Without this the
        // sender keeps its default PT (96) which the remote SDP may not
        // associate with any codec → RTP is received but frames never
        // assemble (Firefox uses PT 109 for Opus vs Chrome 111; for video
        // H.264 uses 102 while VP8 uses 96).
        if (m.formats.isNotEmpty) {
          final negotiatedPt = int.tryParse(m.formats.first);
          if (negotiatedPt != null) sender.payloadType = negotiatedPt;
        }
        if (_debug) _log('[pc] sender ${_transceivers[tIdx].kind} mid=$mid extId=$midExtId pt=${sender.payloadType}');
        tIdx++;
      }
    }
  }


  void _sendSrtpRtp(Uint8List rtpPacket) {
    final srtp = _srtp;
    if (srtp == null) return;
    _transport.sendRtp(srtp.encryptRtp(rtpPacket));
  }

  /// Get statistics (stub — returns empty).
  Future<Map<String, dynamic>> getStats() async => {};

  /// Close the connection.
  Future<void> close() async {
    _setConnectionState(PeerConnectionState.closed);
    _setSignalingState(SignalingState.closed);
    _rtcpTimer?.cancel();
    for (final r in _receivers.values) { r._close(); }
    _receivers.clear();
    for (final ch in _dataChannels.values) { ch.close(); }
    _dataChannels.clear();
    await _transport.stop();
    unawaited(_iceCandidateController.close());
    unawaited(_dataChannelController.close());
    unawaited(_trackController.close());
    unawaited(_rtpPacketController.close());
    unawaited(_iceStateController.close());
    unawaited(_connectionStateController.close());
    unawaited(_signalingStateController.close());
  }

  /// Allocate next data channel ID: offerer uses even, answerer uses odd.
  int _allocateDataChannelId() {
    final isOfferer = _localDescription?.type == SessionDescriptionType.offer;
    // First ID: 0 for offerer, 1 for answerer. Then increment by 2.
    if (_nextDataChannelId == 0 && isOfferer != true) {
      _nextDataChannelId = 1;
    }
    final id = _nextDataChannelId;
    _nextDataChannelId += 2;
    return id;
  }

  // ── Initialization ────────────────────────────────────────────────────────

  void _init() {
    _localCert = EcdsaCertificate.selfSigned();
    _iceUfrag = Csprng.randomHex(4);
    _icePwd = Csprng.randomHex(22);

    _localRtcpSsrc = Csprng.randomUint32();
    // Parse STUN server URLs from configuration.
    final stunServers = <StunServer>[];
    for (final server in configuration.iceServers) {
      for (final url in server.urls) {
        final parsed = StunServer.parse(url);
        if (parsed != null) stunServers.add(parsed);
      }
    }
    _ice = IceStateMachine(controlling: true, stunServers: stunServers);
    _dtls = DtlsStateMachine(role: DtlsRole.client, localCert: _localCert);
    // SCTP role is set dynamically in _onDtlsConnected based on actual DTLS role.
    _sctp = SctpStateMachine(isClient: true);

    _ice.onStateChange = _onIceStateChange;
    _ice.onLocalCandidate = _onLocalCandidate;
    _dtls.onConnected = _onDtlsConnected;
    _dtls.onApplicationData = _onDtlsApplicationData;
    _sctp.onEstablished = _notifySctpEstablished;
    _sctp.onDataChannelOpen = _onRemoteDataChannelOpen;
    _sctp.onData = _onSctpData;

    _transport.attachIce(_ice);
    _transport.attachDtls(_dtls);
    _transport.attachSctp(_sctp);

    _transport.onRtp = _onRtpReceived;
    _transport.onRtcp = _onRtcpReceived;
  }

  bool _transportStarted = false;

  Future<void> _ensureTransportStarted() async {
    if (_transportStarted) return;
    _transportStarted = true;
    await _transport.start();
  }

  // ── Callbacks ─────────────────────────────────────────────────────────────

  void _onIceStateChange(IceState state) {
    switch (state) {
      case IceState.iceChecking:
        _setIceConnectionState(IceConnectionState.checking);
        _setConnectionState(PeerConnectionState.connecting);
      case IceState.iceConnected:
        _setIceConnectionState(IceConnectionState.connected);
        // Don't set PeerConnectionState.connected yet — per W3C spec,
        // connectionState requires BOTH ICE and DTLS to be connected.
        // PeerConnectionState.connected is set in _onDtlsConnected.
        // Start DTLS handshake — delegate to transport so it can schedule
        // the retransmit timer.  The first ClientHello may arrive at the
        // remote peer before its ICE pair is fully validated, so
        // retransmission is essential.
        final pair = _ice.selectedPair;
        if (pair != null) {
          _transport.startDtlsHandshake(
            remoteIp: pair.remote.ip,
            remotePort: pair.remote.port,
          );
        }
      case IceState.iceFailed:
        _setIceConnectionState(IceConnectionState.failed);
        _setConnectionState(PeerConnectionState.failed);
      case IceState.iceClosed:
        _setIceConnectionState(IceConnectionState.closed);
      default:
        break;
    }
  }

  void _onLocalCandidate(IceCandidate candidate) {
    _iceCandidateController.add(PeerConnectionIceEvent(
      candidate: candidate.toSdpLine(),
      sdpMid: '0',
      sdpMLineIndex: 0,
    ));
  }

  void _onDtlsApplicationData(Uint8List data) {
    // Forward decrypted SCTP data to the SCTP state machine
    if (_debug) {
      final hex = data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
      _log('[pc] onDtlsAppData len=${data.length} hex=$hex');
    }
    final pair = _ice.selectedPair;
    if (pair == null) {
      if (_debug) _log('[pc] no selected pair for SCTP');
      return;
    }
    try {
      final result = _sctp.processInput(
          data, remoteIp: pair.remote.ip, remotePort: pair.remote.port);
      if (result.isOk) {
        if (_debug) _log('[pc] sctp output: ${result.value.outputPackets.length} pkts');
        for (final pkt in result.value.outputPackets) {
          if (_debug) {
            final hex = pkt.data.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
            _log('[pc] sctp TX len=${pkt.data.length} hex=$hex');
          }
          _transport.sendSctp(pkt.data);
        }
      } else {
        if (_debug) _log('[pc] sctp error: ${result.error}');
      }
    } catch (e, st) {
      if (_debug) _log('[pc] sctp EXCEPTION: $e\n$st');
    }
  }

  static final bool _debug = Platform.environment['WEBDARTC_DEBUG'] == '1';
  static void _log(String msg) => stderr.writeln(msg);

  void _onDtlsConnected(Uint8List keyMaterial) {
    // W3C: connectionState = "connected" when BOTH ICE and DTLS are up.
    _setConnectionState(PeerConnectionState.connected);

    // Determine SRTP profile from DTLS negotiation (RFC 5764 / RFC 7714).
    final profileId = _dtls.selectedSrtpProfileId;
    final SrtpProfile srtpProfile;
    switch (profileId) {
      case 0x0008:
        srtpProfile = SrtpProfile.aesGcm256;
      case 0x0007:
        srtpProfile = SrtpProfile.aesGcm128;
      case 0x0002:
        srtpProfile = SrtpProfile.aesCm128HmacSha1_32;
      case 0x0001:
      default:
        srtpProfile = SrtpProfile.aesCm128HmacSha1_80;
    }
    if (_debug) _log('[pc] DTLS connected: role=$role srtpProfile=0x${(profileId ?? 0).toRadixString(16)}');
    // Derive SRTP context
    final isClient = role == DtlsRole.client;
    _srtp = SrtpContext.fromKeyMaterial(
      keyMaterial: keyMaterial,
      profile: srtpProfile,
      isClient: isClient,
    );
    _transport.attachSrtp(_srtp!);

    // Set SCTP role to match DTLS role: DTLS client = SCTP client (RFC 8841 §5)
    _sctp.isClient = role == DtlsRole.client;

    // Skip SCTP if this is a media-only session (no data channels).
    if (_transceivers.isNotEmpty && _dataChannels.isEmpty) {
      if (_debug) _log('[pc] media-only session — skipping SCTP');
      // Send periodic RTCP RR to kick-start and sustain Chrome's video encoder.
      // Chrome won't send VP8 until it receives RTCP RR.
      _startRtcpTimer();
      return;
    }

    // SCTP role follows DTLS role: DTLS client = SCTP client
    if (role == DtlsRole.client) {
      // We're the DTLS client → initiate SCTP.
      // Skip if the peer already sent INIT (simultaneous open from Firefox
      // which ignores RFC 8841 §5 and always initiates SCTP).  In that
      // case the SCTP state machine already yielded to the peer's INIT
      // and is handling the handshake as server.
      if (_sctp.receivedRemoteInit) {
        if (_debug) _log('[pc] peer already sent SCTP INIT — skipping connect');
      } else {
        // Delay slightly to let the peer's INIT arrive first when the peer
        // also initiates (Firefox ignores RFC 8841 §5 and always sends INIT).
        // 50 ms is long enough for the peer's first SCTP INIT to arrive via
        // DTLS on loopback, short enough not to impact real-world latency.
        Future<void>.delayed(const Duration(milliseconds: 50), () {
          // Re-check — the peer's INIT may have arrived during the delay,
          // either triggering the yield path or the normal server path.
          if (_sctp.receivedRemoteInit ||
              _sctp.state != SctpState.closed) {
            return;
          }
          final pair = _ice.selectedPair;
          if (pair != null) {
            final sctpResult = _sctp.connect(
                remoteIp: pair.remote.ip, remotePort: pair.remote.port);
            if (sctpResult.isOk) {
              for (final pkt in sctpResult.value.outputPackets) {
                _transport.sendSctp(pkt.data);
              }
            }
          }
        });
      }
    }
    // If DTLS server, Chrome (DTLS client) will send SCTP INIT
  }

  DtlsRole get role => _dtls.role;

  void _onRemoteDataChannelOpen(int streamId, String label, bool ordered) {
    if (_debug) _log('[pc] onDataChannelOpen streamId=$streamId label=$label');
    // Check if this is a locally-created channel receiving DCEP ACK
    final existing = _dataChannels[streamId];
    if (existing != null) {
      if (_debug) _log('[pc] opening existing channel id=$streamId');
      existing._open();
      return;
    }

    // Remote channel (DCEP OPEN received from peer)
    final channel = DataChannel(
      label: label,
      ordered: ordered,
      id: streamId,
    );
    channel._sendCallback = (Uint8List data, {bool binary = true}) {
      final ppid = binary ? SctpPpid.webrtcBinary : SctpPpid.webrtcString;
      _sctp.sendData(data: data, streamId: streamId, ordered: ordered, ppid: ppid);
    };
    channel._open();
    _dataChannels[streamId] = channel;
    _dataChannelController.add(DataChannelEvent(channel));
  }

  void _onSctpData(int streamId, Uint8List data, bool isBinary) {
    _dataChannels[streamId]?._deliverMessage(data, isBinary);
  }

  // ── RTP/RTCP handling ──────────────────────────────────────────────────────

  void _onRtpReceived(Uint8List data, int arrivalUs) {
    final result = RtpParser.parseRtp(data);
    if (result.isErr) return;
    final rtp = result.value;
    final ssrc = rtp.ssrc;
    if (_debug) _log('[pc] RTP received: ssrc=$ssrc pt=${rtp.payloadType} seq=${rtp.sequenceNumber}');

    // Update reception stats for RTCP RR
    final stats = _rtpRecvStats.putIfAbsent(ssrc, () => _RtpRecvStats(ssrc));
    stats.update(rtp.sequenceNumber);

    // Extract transport-cc sequence number from header extension
    if (_twccExtId > 0) {
      if (rtp.headerExtension != null) {
        final elements = rtp.headerExtension!.parseElements();
        for (final ext in elements) {
          if (ext.id == _twccExtId && ext.data.length >= 2) {
            final twccSeq = (ext.data[0] << 8) | ext.data[1];
            _twccRecvLog.add(_TwccEntry(twccSeq, arrivalUs));
            if (_debug && _twccRecvLog.length <= 3) {
              _log('[pc] twcc seq=$twccSeq (ext elements=${elements.length})');
            }
          }
        }
        if (elements.isEmpty && _debug) {
          _log('[pc] headerExt present but 0 elements (profile=0x${rtp.headerExtension!.profile.toRadixString(16)}, dataLen=${rtp.headerExtension!.data.length})');
        }
      } else if (_debug && _receivers.length <= 1) {
        _log('[pc] no headerExtension on RTP pt=${rtp.payloadType} ext=${rtp.extension}');
      }
    }

    _rtpPacketController.add(rtp);

    // Route to per-SSRC receiver
    final existing = _receivers[ssrc];
    if (existing != null) {
      existing._deliver(rtp);
    } else {
      // New SSRC — create receiver and fire onTrack
      final kind = _resolveTrackKind(rtp.payloadType);
      final receiver = RtpReceiver._(kind: kind, ssrc: ssrc);
      _receivers[ssrc] = receiver;
      _trackController.add(TrackEvent(kind: kind, ssrc: ssrc, receiver: receiver));
      receiver._deliver(rtp);
      if (_debug) _log('[pc] onTrack fired: kind=$kind ssrc=$ssrc');
      // Send initial RTCP RR after first packet (triggers Chrome video encoder)
      _sendRtcpRR();
      // Send PLI for video to request an immediate keyframe (RFC 4585 §6.3.1).
      // Without this, the decoder waits for the next periodic keyframe.
      if (kind == 'video') _sendPli(ssrc);
    }
  }

  // Dynamic PT→kind map built from SDP negotiation.
  final Map<int, String> _ptKindMap = {};

  String _resolveTrackKind(int payloadType) {
    // Check dynamically negotiated PTs first (populated from SDP).
    final fromSdp = _ptKindMap[payloadType];
    if (fromSdp != null) return fromSdp;
    // Fallback heuristics for well-known static PTs.
    if (payloadType <= 34) return 'audio'; // RFC 3551 static audio range
    if (payloadType >= 96 && payloadType <= 127) {
      // Dynamic range — check unmatched transceivers
      for (final t in _transceivers) {
        if (!_receivers.values.any((r) => r.kind == t.kind)) return t.kind;
      }
    }
    return 'audio';
  }

  void _onRtcpReceived(Uint8List data) {
    final result = RtpParser.parseRtcp(data);
    if (result.isErr) return;
    for (final pkt in result.value) {
      if (_debug) _log('[pc] RTCP received: ${pkt.runtimeType}');
      if (pkt is RtcpSenderReport) {
        // Update stats with SR info and send RR back
        final stats = _rtpRecvStats[pkt.ssrc];
        if (stats != null) {
          stats.lastSrNtp = ((pkt.ntpTimestampHigh & 0xFFFF) << 16) |
              ((pkt.ntpTimestampLow >> 16) & 0xFFFF);
          stats.lastSrReceivedAt = DateTime.now();
        }
        _sendRtcpRR();
      }
    }
  }

  void _sendPli(int mediaSourceSsrc) {
    // Queue PLI to be included in the next periodic compound RTCP that uses
    // an active sender SSRC (known to Chrome from SDP).  Compounds sent with
    // _localRtcpSsrc are rejected by Chrome because the SSRC is unknown.
    _pendingPliSsrcs.add(mediaSourceSsrc);
    if (_debug) _log('[pc] queued PLI for ssrc=$mediaSourceSsrc');
  }

  void _startRtcpTimer() {
    _rtcpTimer?.cancel();
    // Send RTCP RR + transport-cc every 100ms for fast feedback.
    _rtcpTimer = Timer.periodic(const Duration(milliseconds: 100), (_) => _sendRtcpRR());
    Future<void>.delayed(const Duration(milliseconds: 50), _sendRtcpRR);
  }

  void _sendRtcpRR() {
    final srtp = _srtp;
    if (srtp == null) return;

    // Only include RR blocks for SSRCs that have actually sent packets.
    final blocks = <RtcpReportBlock>[];
    for (final stats in _rtpRecvStats.values) {
      if (stats.highestSeq == 0 && stats.packetsReceived == 0) continue;
      final dlsr = stats.lastSrReceivedAt != null
          ? ((DateTime.now().difference(stats.lastSrReceivedAt!).inMicroseconds *
                  65536) ~/
              1000000)
          : 0;
      blocks.add(RtcpReportBlock(
        ssrc: stats.ssrc,
        fractionLost: 0,
        cumulativeLost: 0,
        extendedHighestSeq: stats.highestSeq,
        jitter: 0,
        lastSr: stats.lastSrNtp,
        delaySinceLastSr: dlsr,
      ));
    }

    // Build compound RTCP: SR/RR + SDES(CNAME) [+ REMB] [+ Transport-CC]
    // RFC 3550 §6.1 requires compound packets with SR/RR + SDES as minimum.
    // Use SR if we are actively sending RTP, RR otherwise.
    final compound = <int>[];

    // Determine SSRC for this compound packet — must be consistent across
    // all sub-packets (SR/RR, SDES, etc.) per RFC 3550 §6.1.
    final activeSenders = _transceivers
        .where((t) => t.sender != null && t.sender!._packetsSent > 0)
        .map((t) => t.sender!)
        .toList();

    // Send SR for an active sender, or RR if no sender is active.
    // When PLI is pending, prefer the video sender so Chrome associates
    // the compound with the video m= line.
    final int compoundSsrc;
    if (activeSenders.isNotEmpty) {
      final sender = (_pendingPliSsrcs.isNotEmpty
          ? activeSenders.where((s) => s.kind == 'video').firstOrNull
          : null) ?? activeSenders.first;
      compoundSsrc = sender.ssrc;
      final now = DateTime.now();
      final ntpSecs = (now.millisecondsSinceEpoch ~/ 1000) + 2208988800; // Unix→NTP epoch
      final ntpFrac = ((now.millisecondsSinceEpoch % 1000) * 4294967296 ~/ 1000);
      compound.addAll(RtcpSenderReport(
        ssrc: compoundSsrc,
        ntpTimestampHigh: ntpSecs & 0xFFFFFFFF,
        ntpTimestampLow: ntpFrac & 0xFFFFFFFF,
        rtpTimestamp: sender._lastRtpTimestamp,
        packetCount: sender._packetsSent,
        octetCount: sender._octetsSent,
        reportBlocks: blocks,
      ).build());
    } else {
      compoundSsrc = _localRtcpSsrc;
      compound.addAll(RtcpReceiverReport(ssrc: compoundSsrc, reportBlocks: blocks).build());
    }
    compound.addAll(RtcpSdes(chunks: [
      RtcpSdesChunk(ssrc: compoundSsrc, items: {1: 'webdartc'}),
    ]).build());

    // REMB for video bandwidth signaling
    if (_transceivers.any((t) => t.kind == 'video')) {
      final remoteSsrcs = _rtpRecvStats.keys.where((ssrc) {
        final s = _rtpRecvStats[ssrc];
        return s != null && s.packetsReceived > 0;
      }).toList();
      if (remoteSsrcs.isNotEmpty) {
        compound.addAll(RtcpRemb(
          senderSsrc: compoundSsrc,
          bitrate: 10000000, // 10 Mbps
          mediaSsrcs: remoteSsrcs,
        ).build());
      }
    }

    // Pending keyframe requests (PLI + FIR, RFC 4585/5104).
    // Only include when compound uses an active sender SSRC (known to
    // Chrome from SDP).  Keep retrying until cleared externally.
    if (_pendingPliSsrcs.isNotEmpty && activeSenders.isNotEmpty) {
      for (final mediaSsrc in _pendingPliSsrcs) {
        // PLI (RFC 4585 §6.3.1)
        compound.addAll(RtcpPli(senderSsrc: compoundSsrc, mediaSourceSsrc: mediaSsrc).build());
        // FIR (RFC 5104 §4.3.1) — some implementations respond to FIR but not PLI
        final fir = Uint8List(20);
        fir[0] = 0x80 | 4; // V=2, FMT=4
        fir[1] = 206; // PT=PSFB
        fir[2] = 0; fir[3] = 4; // length=4
        void w32(Uint8List b, int o, int v) { b[o]=(v>>24)&0xFF; b[o+1]=(v>>16)&0xFF; b[o+2]=(v>>8)&0xFF; b[o+3]=v&0xFF; }
        w32(fir, 4, compoundSsrc); // sender SSRC
        w32(fir, 8, 0); // media source (unused in FIR)
        w32(fir, 12, mediaSsrc); // FCI: target SSRC
        fir[16] = 1; // Seq nr
        compound.addAll(fir);
      }
      if (_debug) _log('[pc] PLI+FIR for ssrcs=$_pendingPliSsrcs (sender=$compoundSsrc)');
    }

    // Transport-cc feedback — use a consistent known SSRC so Chrome's
    // transport-cc processor always matches it to our session.
    final videoSender = _transceivers
        .where((t) => t.kind == 'video' && t.sender != null)
        .map((t) => t.sender!)
        .firstOrNull;
    if (videoSender != null) {
      // mediaSsrc: Chrome expects the SSRC of the media stream being fed
      // back, despite the spec saying 0. Use first known remote video SSRC.
      final remoteVideoSsrc = _receivers.entries
          .where((e) => e.value.kind == 'video')
          .map((e) => e.key)
          .firstOrNull ?? _rtpRecvStats.keys.firstOrNull ?? 0;
      final ccBytes = _buildTransportCcFeedback(videoSender.ssrc, remoteVideoSsrc);
      if (ccBytes != null) compound.addAll(ccBytes);
    }

    _transport.sendRtp(srtp.encryptRtcp(Uint8List.fromList(compound)));
    if (_debug) _log('[pc] sent compound RTCP (${compound.length}b): RR(${blocks.length})');
  }

  Uint8List? _buildTransportCcFeedback(int senderSsrc, int mediaSsrc) {
    if (_twccRecvLog.isEmpty) return null;

    // Consume all pending entries
    final entries = List<_TwccEntry>.from(_twccRecvLog);
    _twccRecvLog.clear();

    // Build seq → arrival map, handling duplicates by keeping earliest.
    final arrivalMap = <int, int>{};
    for (final e in entries) {
      arrivalMap.putIfAbsent(e.seq, () => e.arrivalUs);
    }

    // Determine full sequence range.
    final seqs = arrivalMap.keys.toList()..sort();
    final baseSeq = seqs.first;
    final maxSeq = seqs.last;
    final statusCount = maxSeq - baseSeq + 1;
    final baseTimeUs = arrivalMap[baseSeq]!;

    // Reference time is quantized to 64ms. The first delta captures the
    // sub-64ms remainder so cross-feedback timing stays accurate to 250µs.
    final referenceTimeMs = baseTimeUs ~/ 1000;
    final refTimeQuantizedUs = (referenceTimeMs ~/ 64) * 64 * 1000;

    // Build deltas for the full range [baseSeq, maxSeq].
    // null = not received, non-null = inter-arrival delta in µs.
    final deltas = <int?>[];
    var prevUs = refTimeQuantizedUs; // start from quantized reference, NOT baseTimeUs
    for (var seq = baseSeq; seq <= maxSeq; seq++) {
      final arrival = arrivalMap[seq];
      if (arrival == null) {
        deltas.add(null); // not received
      } else {
        deltas.add(arrival - prevUs);
        prevUs = arrival;
      }
    }

    final fb = RtcpTransportCc(
      senderSsrc: senderSsrc,
      mediaSsrc: mediaSsrc,
      baseSeq: baseSeq,
      referenceTimeMs: referenceTimeMs,
      fbPktCount: _twccFbCount & 0xFF,
      recvDeltasUs: deltas,
    );
    _twccFbCount++;

    final rawFb = fb.build();
    if (_debug) _log('[pc] transport-cc fb: base=$baseSeq count=$statusCount recv=${seqs.length}');
    return rawFb;
  }

  // ── Deferred SCTP actions ─────────────────────────────────────────────────

  final _sctpEstablishedCallbacks = <void Function()>[];
  bool _sctpEstablished = false;

  void _onSctpEstablished(void Function() callback) {
    if (_sctpEstablished) {
      callback();
    } else {
      _sctpEstablishedCallbacks.add(callback);
    }
  }

  void _notifySctpEstablished() {
    _sctpEstablished = true;
    for (final cb in _sctpEstablishedCallbacks) { cb(); }
    _sctpEstablishedCallbacks.clear();
  }

  // ── State management ──────────────────────────────────────────────────────

  void _setSignalingState(SignalingState state) {
    if (_signalingState == state) return;
    _signalingState = state;
    _signalingStateController.add(state);
  }

  void _setIceConnectionState(IceConnectionState state) {
    if (_iceConnectionState == state) return;
    _iceConnectionState = state;
    _iceStateController.add(state);
  }

  void _setConnectionState(PeerConnectionState state) {
    if (_connectionState == state) return;
    _connectionState = state;
    _connectionStateController.add(state);
  }
}

final class _RtpRecvStats {
  final int ssrc;
  int highestSeq = 0;
  int packetsReceived = 0;
  int lastSrNtp = 0;
  DateTime? lastSrReceivedAt;

  _RtpRecvStats(this.ssrc);

  void update(int seq) {
    packetsReceived++;
    if (seq > highestSeq) highestSeq = seq;
  }
}

final class _TwccEntry {
  final int seq;
  final int arrivalUs;
  const _TwccEntry(this.seq, this.arrivalUs);
}

final class _MediaTransceiver {
  final String kind; // 'audio' or 'video'
  final String direction; // 'sendrecv', 'recvonly', 'sendonly', 'inactive'
  final List<String>? preferredCodecs;
  RtpSender? sender;
  _MediaTransceiver({
    required this.kind,
    this.direction = 'sendrecv',
    this.preferredCodecs,
  });
}
