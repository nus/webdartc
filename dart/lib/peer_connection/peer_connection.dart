import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform, stderr;
import 'dart:typed_data';

import '../api/media_engine.dart';
import '../api/setting_engine.dart';
import '../api/stats.dart';
import '../codec/default_codecs.dart';
import '../core/byte_io.dart';
import '../crypto/csprng.dart';
import '../crypto/ecdsa.dart';
import '../dtls/state_machine.dart';
import '../ice/state_machine.dart';
import '../media/media_stream.dart';
import '../media/media_stream_track.dart';
import '../media/receive_pipeline.dart';
import '../rtp/parser.dart';
import '../rtp/receive_stats.dart';
import '../rtp/rtcp_math.dart';
import '../rtp/rtp_transport.dart';
import '../sctp/state_machine.dart';
import '../sdp/parser.dart';
import '../srtp/context.dart';
import '../transport/transport_controller.dart';
import '../turn/state_machine.dart';

part 'data_channel.dart';
part 'events.dart';
part 'rtcp_session.dart';
part 'sdp_negotiator.dart';
part 'stats_collector.dart';

/// ICE server configuration.
final class IceServer {
  final List<String> urls;
  final String? username;
  final String? credential;

  const IceServer({required this.urls, this.username, this.credential});
}

/// W3C `RTCIceTransportPolicy` (WebRTC §4.2.2).
///
/// `relay` restricts ICE to TURN-derived `relay` candidates: no host or
/// srflx candidates are gathered or paired, and host/srflx candidates
/// arriving from the peer are dropped.
enum IceTransportPolicy { all, relay }

/// PeerConnection configuration.
final class PeerConnectionConfiguration {
  final List<IceServer> iceServers;
  final IceTransportPolicy iceTransportPolicy;
  final String bundlePolicy; // "balanced" | "max-bundle" | "max-compat"
  final String rtcpMuxPolicy;

  const PeerConnectionConfiguration({
    this.iceServers = const [],
    this.iceTransportPolicy = IceTransportPolicy.all,
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

/// WebRTC PeerConnection (W3C API without "RTC" prefix).
///
/// Maps to W3C RTCPeerConnection.
/// Deprecated W3C APIs are not implemented.
final class PeerConnection {
  /// The active configuration. Replaced wholesale by [setConfiguration]; the
  /// constructor's value is the initial one returned by [getConfiguration].
  PeerConnectionConfiguration configuration;

  // State
  SignalingState _signalingState = SignalingState.stable;
  IceConnectionState _iceConnectionState = IceConnectionState.iceNew;
  IceGatheringState _iceGatheringState = IceGatheringState.newState;
  PeerConnectionState _connectionState = PeerConnectionState.newState;

  // Protocol modules
  final _transport = TransportController();
  late final IceStateMachine _ice;
  late final DtlsStateMachine _dtls;
  late final SctpStateMachine _sctp;
  SrtpContext? _srtp;

  bool get _relayOnly =>
      configuration.iceTransportPolicy == IceTransportPolicy.relay;

  // Local credentials
  late final EcdsaCertificate _localCert;

  // Collaborators (same-library parts): SDP offer/answer + ICE credentials,
  // RTCP send/receive + reception stats, and getStats assembly.
  late final SdpNegotiator _negotiation = SdpNegotiator(this);
  late final RtcpSession _rtcp = RtcpSession(this);
  late final StatsCollector _stats = StatsCollector(this);

  // Data channels
  final Map<int, DataChannel> _dataChannels = {};
  int _nextDataChannelId = 0; // even for offerer, odd for answerer

  // Media transceivers
  final List<RtpTransceiver> _transceivers = [];
  final Map<int, RtpReceiver> _receivers = {}; // SSRC → receiver

  // Stream controllers
  final _iceCandidateController =
      StreamController<PeerConnectionIceEvent>.broadcast();
  final _iceCandidateErrorController =
      StreamController<IceCandidateError>.broadcast();
  final _dataChannelController =
      StreamController<DataChannelEvent>.broadcast();
  final _trackController = StreamController<TrackEvent>.broadcast();
  final _rtpPacketController = StreamController<RtpPacket>.broadcast();
  final _iceStateController = StreamController<IceConnectionState>.broadcast();
  final _iceGatheringStateController =
      StreamController<IceGatheringState>.broadcast();
  final _connectionStateController =
      StreamController<PeerConnectionState>.broadcast();
  final _signalingStateController =
      StreamController<SignalingState>.broadcast();
  final _negotiationNeededController = StreamController<void>.broadcast();

  /// W3C negotiation-needed flag — set when the m-line/transport set changes
  /// while stable, cleared once a fresh local offer is applied. Guards against
  /// firing `onNegotiationNeeded` more than once per pending change.
  bool _negotiationNeeded = false;

  /// Network / ICE settings. Pass via the `settingEngine` constructor
  /// parameter (typically through [Webdartc.createPeerConnection]); the
  /// default value is sufficient for single-interface, no-bind-control
  /// callers.
  final SettingEngine settingEngine;

  /// Codec capabilities to advertise in offer / answer SDP. When the
  /// constructor is given none, defaults to [MediaEngine.forPlatform] — VP8 +
  /// H.264 + Opus, narrowed to what this platform can actually encode/decode
  /// (e.g. VP8 is dropped on an Android device whose MediaCodec lacks it).
  ///
  /// Independent from the encoder/decoder backend registry — a custom engine is
  /// taken verbatim and is NOT availability-gated, so an app can advertise a
  /// codec it forwards as raw RTP via [onRtpPacket] / [RtpSender.sendRtp]
  /// without registering a backend. The flip side: advertising a codec that has
  /// no registered backend negotiates fine but then fails to decode incoming
  /// media — drive such codecs through the raw-RTP surface, not [onTrack].
  final MediaEngine mediaEngine;

  PeerConnection({
    required this.configuration,
    this.settingEngine = const SettingEngine(),
    MediaEngine? mediaEngine,
    bool autoRegisterCodecs = true,
  }) : mediaEngine = mediaEngine ?? MediaEngine.forPlatform() {
    // Register the bundled codec backends so the W3C receive path
    // (`onTrack` → `track.onVideoFrame`) decodes out of the box. Only stores
    // factory closures — native libraries load lazily on first use, so this
    // costs nothing for data-channel-only connections. Opt out to control
    // which backends are available (then register a subset yourself).
    if (autoRegisterCodecs) registerDefaultCodecs();
    _init();
  }

  // ── State properties ──────────────────────────────────────────────────────

  SignalingState get signalingState => _signalingState;
  IceConnectionState get iceConnectionState => _iceConnectionState;

  /// W3C `iceGatheringState`: `newState` before gathering starts, `gathering`
  /// while local candidates are collected, `complete` once finished.
  IceGatheringState get iceGatheringState => _iceGatheringState;
  PeerConnectionState get connectionState => _connectionState;
  SessionDescription? get localDescription => _negotiation._localDescription;
  SessionDescription? get remoteDescription => _negotiation._remoteDescription;

  // W3C current/pending split, derived from the last-set description and the
  // signaling state: a side's description is "pending" exactly while that side
  // owns the in-flight offer/pranswer, and "current" otherwise.
  bool get _localPending =>
      _signalingState == SignalingState.haveLocalOffer ||
      _signalingState == SignalingState.haveLocalPrAnswer;
  bool get _remotePending =>
      _signalingState == SignalingState.haveRemoteOffer ||
      _signalingState == SignalingState.haveRemotePrAnswer;

  /// W3C: the description currently in negotiation, or null when stable.
  SessionDescription? get pendingLocalDescription =>
      _localPending ? _negotiation._localDescription : null;
  SessionDescription? get pendingRemoteDescription =>
      _remotePending ? _negotiation._remoteDescription : null;

  /// W3C: the last successfully negotiated description.
  SessionDescription? get currentLocalDescription =>
      _localPending ? null : _negotiation._localDescription;
  SessionDescription? get currentRemoteDescription =>
      _remotePending ? null : _negotiation._remoteDescription;

  /// W3C `getConfiguration()` — the configuration this connection was created
  /// with.
  PeerConnectionConfiguration getConfiguration() => configuration;

  /// W3C `setConfiguration()` — update the active configuration. Per spec the
  /// `bundlePolicy` and `rtcpMuxPolicy` are immutable after construction;
  /// changing either throws (W3C `InvalidModificationError`). `iceServers` and
  /// `iceTransportPolicy` may change and take effect on the next ICE gather.
  void setConfiguration(PeerConnectionConfiguration config) {
    if (_signalingState == SignalingState.closed) {
      throw StateError('PeerConnection is closed');
    }
    if (config.bundlePolicy != configuration.bundlePolicy) {
      throw StateError('bundlePolicy cannot be changed after construction');
    }
    if (config.rtcpMuxPolicy != configuration.rtcpMuxPolicy) {
      throw StateError('rtcpMuxPolicy cannot be changed after construction');
    }
    configuration = config;
  }

  /// W3C `restartIce()` — regenerate the local ICE credentials so the next
  /// offer performs an ICE restart (RFC 8445 §9). The caller must renegotiate
  /// afterwards (`createOffer` → `setLocalDescription` → exchange); the peer
  /// auto-restarts when it sees the changed credentials in the offer.
  void restartIce() {
    _negotiation._regenerateIceCredentials();
    _negotiation._iceRestartPending = true;
  }

  // ── Event streams ─────────────────────────────────────────────────────────

  Stream<PeerConnectionIceEvent> get onIceCandidate =>
      _iceCandidateController.stream;

  /// W3C `icecandidateerror` — a STUN gathering request failed (server error
  /// response or timeout).
  Stream<IceCandidateError> get onIceCandidateError =>
      _iceCandidateErrorController.stream;
  Stream<DataChannelEvent> get onDataChannel => _dataChannelController.stream;

  /// W3C `negotiationneeded` — fires when adding/removing a track, transceiver,
  /// or the first data channel makes the current local description stale and a
  /// new offer/answer exchange is required.
  Stream<void> get onNegotiationNeeded => _negotiationNeededController.stream;
  Stream<TrackEvent> get onTrack => _trackController.stream;
  /// Stream of received RTP packets (parsed, after SRTP decryption).
  Stream<RtpPacket> get onRtpPacket => _rtpPacketController.stream;

  Stream<IceConnectionState> get onIceConnectionStateChange =>
      _iceStateController.stream;
  Stream<IceGatheringState> get onIceGatheringStateChange =>
      _iceGatheringStateController.stream;
  Stream<PeerConnectionState> get onConnectionStateChange =>
      _connectionStateController.stream;
  Stream<SignalingState> get onSignalingStateChange =>
      _signalingStateController.stream;

  /// Snapshot of TURN allocations the underlying transport is driving.
  /// Primarily for tests + diagnostics.
  List<TurnAllocation> get turnAllocations => _transport.turnAllocations;

  // ── W3C API ───────────────────────────────────────────────────────────────

  /// Create an SDP offer.
  Future<SessionDescription> createOffer() async {
    if (_signalingState != SignalingState.stable &&
        _signalingState != SignalingState.haveLocalOffer) {
      throw StateError('createOffer: invalid state $_signalingState');
    }
    return _negotiation.createOffer();
  }

  /// Create an SDP answer based on the remote offer (RFC 3264).
  Future<SessionDescription> createAnswer() async {
    if (_signalingState != SignalingState.haveRemoteOffer) {
      throw StateError('createAnswer: invalid state $_signalingState');
    }
    return _negotiation.createAnswer();
  }

  /// Set the local description and begin ICE gathering.
  ///
  /// Throws when [desc.sdp] doesn't parse — earlier code silently
  /// dropped malformed local SDPs, leaving the description field
  /// and its parsed cache out of sync. `createOffer` / `createAnswer`
  /// produce well-formed SDP, so the throw mainly catches a caller
  /// passing hand-rolled bytes.
  Future<void> setLocalDescription(SessionDescription desc) =>
      _negotiation.setLocalDescription(desc);

  /// Set the remote description.
  Future<void> setRemoteDescription(SessionDescription desc) =>
      _negotiation.setRemoteDescription(desc);

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
      final result = _sctp.sendData(
        data: data,
        streamId: id,
        ordered: opts.ordered,
        ppid: _dataChannelPpid(data, binary),
      );
      if (result.isOk) {
        for (final pkt in result.value.outputPackets) {
          _transport.sendSctp(pkt.data);
        }
        // RFC 4960 §6.3: schedule T3-rtx so a lost DATA chunk
        // gets retransmitted. Discarding this timeout (as the code
        // previously did) leaves un-ACKed chunks pending forever and
        // the DC stalls under any packet loss.
        _transport.scheduleSctpTimeout(result.value.nextTimeout);
      }
    };
    channel._closeCallback = () => _resetSctpStream(id);
    _dataChannels[id] = channel;

    // Send DCEP OPEN once SCTP is established. Defer to a microtask so the
    // COOKIE-ACK that just established us is flushed to the wire first —
    // otherwise the OPEN (sent synchronously while we process COOKIE-ECHO)
    // overtakes it and can reach a peer still in COOKIE-ECHOED, which
    // correctly discards it and only recovers on the slow T3-rtx retransmit.
    _onSctpEstablished(() => scheduleMicrotask(() {
          final result = _sctp.openDataChannel(
            label: label,
            ordered: opts.ordered,
            streamId: id,
          );
          if (result.isOk) {
            for (final pkt in result.value.outputPackets) {
              _transport.sendSctp(pkt.data);
            }
            // Same T3-rtx scheduling reason as the data send callback above.
            _transport.scheduleSctpTimeout(result.value.nextTimeout);
          }
        }));

    // The first data channel introduces the `application` m-line, so the
    // current local description (if any) is now stale.
    if (_dataChannels.length == 1) _markNegotiationNeeded();
    return channel;
  }

  /// Add a media transceiver (audio or video).
  ///
  /// [preferredCodecs] is an ordered list of codec names (e.g. `['H264', 'VP8']`)
  /// to offer, in preference order. If null, a library default is used.
  RtpTransceiver addTransceiver(String kind, {
    String direction = 'sendrecv',
    List<String>? preferredCodecs,
  }) {
    final dir = RtpTransceiverDirection.fromToken(direction);
    final t = RtpTransceiver._(
      kind: kind, direction: dir, preferredCodecs: preferredCodecs);
    // Create sender if direction includes sending
    if (dir == RtpTransceiverDirection.sendrecv ||
        dir == RtpTransceiverDirection.sendonly) {
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
    _markNegotiationNeeded();
    return t;
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

  /// W3C: Stop a sender from sending its track.
  ///
  /// Detaches the track and downgrades the owning transceiver's direction
  /// (`sendrecv`→`recvonly`, `sendonly`→`inactive`), so the next negotiation
  /// no longer offers to send. The transceiver and receiver are kept, matching
  /// the spec (the m-line is reused on renegotiation). A sender not owned by
  /// this connection, or already detached, is a no-op.
  void removeTrack(RtpSender sender) {
    if (_signalingState == SignalingState.closed) {
      throw StateError('PeerConnection is closed');
    }
    final t = _transceivers.where((t) => t.sender == sender).firstOrNull;
    if (t == null || sender._track == null) return;
    sender._track = null;
    t._direction = switch (t._direction) {
      RtpTransceiverDirection.sendrecv => RtpTransceiverDirection.recvonly,
      RtpTransceiverDirection.sendonly => RtpTransceiverDirection.inactive,
      final d => d,
    };
    _markNegotiationNeeded();
  }

  /// Get all RTP senders (for sending media).
  List<RtpSender> getSenders() => List.unmodifiable(
      _transceivers.where((t) => t.sender != null).map((t) => t.sender!));

  /// W3C: all media transceivers, in creation order.
  List<RtpTransceiver> getTransceivers() => List.unmodifiable(_transceivers);

  /// W3C: all RTP receivers that have produced an incoming stream.
  List<RtpReceiver> getReceivers() => List.unmodifiable(_receivers.values);

  void _sendSrtpRtp(Uint8List rtpPacket) {
    final srtp = _srtp;
    if (srtp == null) return;
    _transport.sendRtp(srtp.encryptRtp(rtpPacket));
  }

  /// Snapshot of stats across this PeerConnection's transport, ICE
  /// agent, and data channels. W3C §8 `RTCStatsReport`.
  ///
  /// Returned counters are monotonic; callers compute deltas across
  /// snapshots themselves.
  Future<RtcStatsReport> getStats() {
    // Assembly is synchronous: no awaits, just counter snapshots into
    // typed entries. Returning via `Future.value` keeps the W3C
    // Promise-shaped API without forcing the extra microtask `async`
    // would queue per call.
    return Future.value(_stats.collect());
  }

  /// Close the connection.
  Future<void> close() async {
    _setConnectionState(PeerConnectionState.closed);
    _setSignalingState(SignalingState.closed);
    _rtcp._close();
    for (final r in _receivers.values) { r._close(); }
    _receivers.clear();
    // Tear down channels immediately — the whole transport is going away, so
    // a graceful SCTP stream reset would never complete.
    for (final ch in _dataChannels.values) { ch._finalizeClose(); }
    _dataChannels.clear();
    await _transport.stop();
    unawaited(_iceCandidateController.close());
    unawaited(_iceCandidateErrorController.close());
    unawaited(_dataChannelController.close());
    unawaited(_trackController.close());
    unawaited(_rtpPacketController.close());
    unawaited(_iceStateController.close());
    unawaited(_iceGatheringStateController.close());
    unawaited(_connectionStateController.close());
    unawaited(_signalingStateController.close());
    unawaited(_negotiationNeededController.close());
  }

  /// Allocate next data channel ID: offerer uses even, answerer uses odd.
  int _allocateDataChannelId() {
    final isOfferer =
        _negotiation._localDescription?.type == SessionDescriptionType.offer;
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
    // Split iceServers into STUN and TURN forms. STUN URLs are gathered
    // for srflx discovery; TURN URLs become allocations driven by the
    // transport (relay candidates emitted on Allocate success).
    final stunServers = <StunServer>[];
    final turnServers = <TurnServer>[];
    for (final server in configuration.iceServers) {
      for (final url in server.urls) {
        final stun = StunServer.parse(url);
        if (stun != null) {
          stunServers.add(stun);
          continue;
        }
        final turn = TurnServer.parse(url,
            username: server.username, credential: server.credential);
        if (turn != null) turnServers.add(turn);
      }
    }
    _ice = IceStateMachine(
      controlling: true,
      stunServers: stunServers,
      relayOnly: _relayOnly,
    );
    _transport.attachTurnServers(turnServers);
    _dtls = DtlsStateMachine(role: DtlsRole.client, localCert: _localCert);
    // SCTP role is set dynamically in _onDtlsConnected based on actual DTLS role.
    _sctp = SctpStateMachine(isClient: true);

    _ice.onStateChange = _onIceStateChange;
    _ice.onLocalCandidate = _onLocalCandidate;
    _ice.onCandidateError = (e) {
      if (!_iceCandidateErrorController.isClosed) {
        _iceCandidateErrorController.add(e);
      }
    };
    _dtls.onConnected = _onDtlsConnected;
    _dtls.onApplicationData = _onDtlsApplicationData;
    _sctp.onEstablished = _notifySctpEstablished;
    _sctp.onDataChannelOpen = _onRemoteDataChannelOpen;
    _sctp.onData = _onSctpData;
    _sctp.onStreamReset = _onSctpStreamReset;
    _sctp.onBytesAcked = (streamId, bytes) =>
        _dataChannels[streamId]?._onBytesAcked(bytes);

    _transport.attachIce(_ice);
    _transport.attachDtls(_dtls);
    _transport.attachSctp(_sctp);

    _transport.onRtp = _onRtpReceived;
    _transport.onRtcp = _rtcp._onRtcpReceived;
  }

  bool _transportStarted = false;
  bool _dtlsHandshakeStarted = false;

  Future<void> _ensureTransportStarted() async {
    if (_transportStarted) return;
    _transportStarted = true;
    await _transport.start(settingEngine: settingEngine);
  }

  // ── Callbacks ─────────────────────────────────────────────────────────────

  void _onIceStateChange(IceState state) {
    // Derive the W3C gathering state from the ICE agent's combined state.
    _setIceGatheringState(switch (state) {
      IceState.iceNew => IceGatheringState.newState,
      IceState.iceGathering => IceGatheringState.gathering,
      // Once gathering finishes (and for every later state) it stays complete.
      _ => IceGatheringState.complete,
    });

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
        // retransmission is essential. Only once: an ICE restart re-reaches
        // `iceConnected`, but DTLS (and SCTP/SRTP) persist over the new pair
        // and must not be re-handshaked.
        final pair = _ice.selectedPair;
        if (pair != null && !_dtlsHandshakeStarted) {
          _dtlsHandshakeStarted = true;
          _transport.startDtlsHandshake(
            remoteIp: pair.remote.ip,
            remotePort: pair.remote.port,
          );
        }
      case IceState.iceDisconnected:
        // Consent freshness lapsed (RFC 7675) — signal the transient-loss
        // state; a subsequent ICE restart can recover.
        _setIceConnectionState(IceConnectionState.disconnected);
        _setConnectionState(PeerConnectionState.disconnected);
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
      _rtcp._startTimer();
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
      _sctp.sendData(
          data: data,
          streamId: streamId,
          ordered: ordered,
          ppid: _dataChannelPpid(data, binary));
    };
    channel._closeCallback = () => _resetSctpStream(streamId);
    channel._open();
    _dataChannels[streamId] = channel;
    _dataChannelController.add(DataChannelEvent(channel));
  }

  void _onSctpData(int streamId, Uint8List data, bool isBinary) {
    _dataChannels[streamId]?._deliverMessage(data, isBinary);
  }

  /// Initiate an SCTP stream reset to close a data channel (RFC 8831 §6.7).
  void _resetSctpStream(int streamId) {
    final result = _sctp.resetStreams([streamId]);
    if (result.isOk) {
      for (final pkt in result.value.outputPackets) {
        _transport.sendSctp(pkt.data);
      }
      _transport.scheduleSctpTimeout(result.value.nextTimeout);
    }
  }

  /// A stream reset completed (RFC 6525) — finalize the channel's close.
  void _onSctpStreamReset(int streamId) {
    _dataChannels[streamId]?._finalizeClose();
  }

  /// SCTP PPID for a data-channel message (RFC 8831 §6.6). An empty
  /// message uses the "Empty" PPID so the SCTP layer can carry it as a
  /// single padding byte instead of an invalid zero-length DATA chunk.
  static int _dataChannelPpid(Uint8List data, bool binary) {
    if (data.isEmpty) {
      return binary ? SctpPpid.webrtcBinaryEmpty : SctpPpid.webrtcStringEmpty;
    }
    return binary ? SctpPpid.webrtcBinary : SctpPpid.webrtcString;
  }

  // ── RTP/RTCP handling ──────────────────────────────────────────────────────

  void _onRtpReceived(Uint8List data, int arrivalUs) {
    final result = RtpParser.parseRtp(data);
    if (result.isErr) return;
    final rtp = result.value;
    final ssrc = rtp.ssrc;
    if (_debug) _log('[pc] RTP received: ssrc=$ssrc pt=${rtp.payloadType} seq=${rtp.sequenceNumber}');

    // Update reception stats for RTCP RR + getStats inboundRtp. Resolve the
    // codec (kind + clock rate) once, on first bind — not per packet.
    final stats =
        _rtcp._rtpRecvStats.putIfAbsent(ssrc, () => _RtpRecvStats(ssrc));
    if (!stats.isBound) {
      final recvKind = _negotiation._resolveTrackKind(rtp.payloadType);
      stats.bind(
        kind: recvKind,
        payloadType: rtp.payloadType,
        clockRate: _negotiation._clockRateForPt(rtp.payloadType, recvKind),
      );
    }
    stats.update(
      seq: rtp.sequenceNumber,
      rtpTimestamp: rtp.timestamp,
      arrivalUs: arrivalUs,
      payloadBytes: rtp.payload.length,
    );

    // Extract transport-cc sequence number from header extension
    _rtcp._recordTwcc(rtp, arrivalUs);

    _rtpPacketController.add(rtp);

    // Route to per-SSRC receiver
    final existing = _receivers[ssrc];
    if (existing != null) {
      existing._deliver(rtp, arrivalUs);
    } else {
      // New SSRC — create receiver and fire onTrack
      final kind = _negotiation._resolveTrackKind(rtp.payloadType);
      final receiver = RtpReceiver._(
        kind: kind,
        ssrc: ssrc,
        codecKey: _negotiation._codecForPt(rtp.payloadType),
        clockRate: _negotiation._clockRateForPt(rtp.payloadType, kind),
        channels: _negotiation._channelsForPt(rtp.payloadType),
        requestKeyframe: () => _rtcp._sendPli(ssrc),
      );
      _receivers[ssrc] = receiver;
      // Associate the receiver with a matching transceiver (W3C: each
      // transceiver has one receiver) so getTransceivers() reflects it.
      for (final t in _transceivers) {
        if (t.kind == kind && t.receiver == null && !t.stopped) {
          t._receiver = receiver;
          break;
        }
      }
      _trackController.add(TrackEvent(
          kind: kind, ssrc: ssrc, receiver: receiver, track: receiver.track));
      receiver._deliver(rtp, arrivalUs);
      if (_debug) _log('[pc] onTrack fired: kind=$kind ssrc=$ssrc');
      // Send initial RTCP RR after first packet (triggers Chrome video encoder)
      _rtcp._sendRtcpRR();
      // Send PLI for video to request an immediate keyframe (RFC 4585 §6.3.1).
      // Without this, the decoder waits for the next periodic keyframe.
      if (kind == 'video') _rtcp._sendPli(ssrc);
    }
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

  /// Raise the W3C negotiation-needed flag and, if we're stable, fire
  /// `onNegotiationNeeded` on a microtask (so a burst of `addTrack` calls
  /// coalesces into one event). The flag is cleared when the next local offer
  /// is applied in [setLocalDescription].
  void _markNegotiationNeeded() {
    if (_negotiationNeeded || _signalingState == SignalingState.closed) return;
    _negotiationNeeded = true;
    scheduleMicrotask(() {
      if (_negotiationNeeded &&
          _signalingState == SignalingState.stable &&
          !_negotiationNeededController.isClosed) {
        _negotiationNeededController.add(null);
      }
    });
  }

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

  void _setIceGatheringState(IceGatheringState state) {
    if (_iceGatheringState == state) return;
    _iceGatheringState = state;
    _iceGatheringStateController.add(state);
  }

  void _setConnectionState(PeerConnectionState state) {
    if (_connectionState == state) return;
    _connectionState = state;
    _connectionStateController.add(state);
  }
}

