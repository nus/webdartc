import 'dart:io' show Platform, stderr;
import 'dart:typed_data';

import '../core/state_machine.dart';
import '../crypto/csprng.dart';
import 'crc32c.dart';
import 'chunk.dart';
import 'dcep.dart';

export 'dcep.dart';

/// SCTP over DTLS (RFC 8261) + DCEP (RFC 8832) state machine.
///
/// MTU = 1200 bytes (RFC 8261 §5).
final class SctpStateMachine implements ProtocolStateMachine {
  static const int _mtu = 1200;
  static const int _defaultRwnd = 131072; // 128 KB
  static const int _maxStreams = 65535;

  SctpState _state = SctpState.closed;

  // Connection parameters
  bool _isClient; // used via setter
  int _localVerificationTag = 0;
  int _remoteVerificationTag = 0;
  int _localInitialTsn = 0;
  int _remoteInitialTsn = 0;
  int _cumulativeRemoteTsn = 0; // highest in-order TSN received
  int _localTsn = 0;
  int _remoteRwnd = _defaultRwnd;
  final int _localRwnd = _defaultRwnd;

  // Cookie for stateless association setup (RFC 4960 §5.1)
  Uint8List? _cookie;

  // Stream state
  // stream ID → SSN (stream sequence number for ordered delivery)
  final Map<int, int> _sendSsn = {};
  final Map<int, int> _recvSsn = {};
  // stream ID → label (from DCEP OPEN)
  final Map<int, String> _channelLabels = {};
  // pending OPEN acks (stream ID → DcepOpenMessage)
  final Map<int, DcepOpenMessage> _pendingOpen = {};

  // Retransmission queue keyed by TSN
  final Map<int, _PendingData> _retransmitQueue = {};

  int _retransmitCount = 0;
  static const int _t3RtxMs = 3000;
  // RFC 4960 §8.1: Association.Max.Retrans default = 10
  static const int _maxRetransmit = 10;

  // Remote address
  String _remoteIp = '';
  int _remotePort = 0;

  // Local SCTP port (fixed for WebRTC: 5000)
  static const int _sctpPort = 5000;
  static final bool _debug = (() {
    try { return Platform.environment['WEBDARTC_DEBUG'] == '1'; }
    catch (_) { return false; }
  })();

  /// Called when the SCTP association is established.
  void Function()? onEstablished;

  /// Called when a data channel is opened.
  void Function(int streamId, String label, bool ordered)? onDataChannelOpen;

  /// Called when data arrives on a stream.
  void Function(int streamId, Uint8List data, bool isBinary)? onData;

  SctpStateMachine({bool isClient = true}) : _isClient = isClient;

  /// Update the SCTP role (must be called before connect/processInput).
  set isClient(bool value) => _isClient = value;

  SctpState get state => _state;

  // ── Public API ────────────────────────────────────────────────────────────

  /// Start the SCTP association (send INIT).
  Result<ProcessResult, ProtocolError> connect({
    required String remoteIp,
    required int remotePort,
  }) {
    _remoteIp = remoteIp;
    _remotePort = remotePort;
    _localVerificationTag = Csprng.randomUint32();
    _localInitialTsn = Csprng.randomUint32();
    _localTsn = _localInitialTsn;
    return _sendInit();
  }

  /// Open a data channel (send DCEP OPEN on given stream).
  Result<ProcessResult, ProtocolError> openDataChannel({
    required String label,
    required bool ordered,
    int streamId = 0,
    String protocol = '',
  }) {
    if (_state != SctpState.established) {
      return Err(const StateError('SCTP: not established'));
    }
    final dcepType = ordered
        ? DcepChannelType.reliable
        : DcepChannelType.reliableUnordered;
    final openMsg = DcepOpenMessage(
      channelType: dcepType,
      label: label,
      protocol: protocol,
    );
    _pendingOpen[streamId] = openMsg;
    final payload = openMsg.encode();
    return sendData(
      data: payload,
      streamId: streamId,
      ordered: ordered,
      ppid: SctpPpid.webrtcDcep,
    );
  }

  /// Send data on a stream.
  Result<ProcessResult, ProtocolError> sendData({
    required Uint8List data,
    required int streamId,
    required bool ordered,
    int ppid = SctpPpid.webrtcBinary,
  }) {
    if (_state != SctpState.established) {
      return Err(const StateError('SCTP: not established'));
    }

    final ssn = _sendSsn[streamId] ?? 0;
    if (ordered) { _sendSsn[streamId] = (ssn + 1) & 0xFFFF; }

    // Fragment if needed (MTU - SCTP overhead ~12+16 bytes)
    const maxUserData = _mtu - 28;
    final chunks = <SctpDataChunk>[];
    for (var offset = 0; offset < data.length || data.isEmpty; ) {
      final end = (offset + maxUserData).clamp(0, data.length);
      final isFirst = offset == 0;
      final isLast  = end == data.length;
      final flags = (isFirst ? SctpDataChunk.flagBegin : 0) |
                    (isLast  ? SctpDataChunk.flagEnd   : 0) |
                    (ordered ? 0 : SctpDataChunk.flagUnordered);
      final tsn = _localTsn;
      _localTsn = (_localTsn + 1) & 0xFFFFFFFF;
      chunks.add(SctpDataChunk(
        flags: flags,
        tsn: tsn,
        streamId: streamId,
        streamSeqNum: ssn,
        ppid: ppid,
        userData: data.isEmpty ? Uint8List(0) : data.sublist(offset, end),
      ));
      _pendingData(tsn, data.isEmpty ? Uint8List(0) : data.sublist(offset, end),
          streamId, ssn, ppid, flags);
      if (data.isEmpty) { break; }
      offset = end;
    }

    final packets = [
      for (final c in chunks) _buildPacket([c])
    ];

    // Schedule T3-rtx timer using first chunk's TSN
    final firstTsn = chunks.first.tsn;
    final timeout = Timeout(
      at: DateTime.now().add(const Duration(milliseconds: _t3RtxMs)),
      token: SctpT3RtxToken(firstTsn),
    );
    return Ok(ProcessResult(outputPackets: packets, nextTimeout: timeout));
  }

  // ── ProtocolStateMachine ──────────────────────────────────────────────────

  @override
  Result<ProcessResult, ProtocolError> processInput(
    Uint8List packet, {
    required String remoteIp,
    required int remotePort,
  }) {
    _remoteIp = remoteIp;
    _remotePort = remotePort;

    if (packet.length < 12) {
      return Err(const ParseError('SCTP: packet too short'));
    }

    // Validate common header
    final hdr = SctpCommonHeader.parse(packet);
    if (hdr == null) { return Err(const ParseError('SCTP: bad common header')); }

    // Validate verification tag (except for INIT which has tag=0)
    final chunks = parseChunks(packet, 12);
    if (chunks.isEmpty) { return const Ok(ProcessResult.empty); }

    // INIT has VTag=0; all others must match local tag
    if (chunks.first is! SctpInitChunk &&
        hdr.verificationTag != _localVerificationTag) {
      if (_debug) {
        stderr.writeln('[sctp] VTag mismatch: got=0x${hdr.verificationTag.toRadixString(16)} '
            'expected=0x${_localVerificationTag.toRadixString(16)} '
            'chunkType=${chunks.first.runtimeType} state=$_state');
      }
      return const Ok(ProcessResult.empty); // silently discard
    }
    if (_debug && chunks.isNotEmpty) {
      stderr.writeln('[sctp] processing ${chunks.length} chunks, first=${chunks.first.runtimeType} state=$_state');
    }

    final results = <OutputPacket>[];
    Timeout? nextTimeout;

    for (final chunk in chunks) {
      final r = _processChunk(chunk);
      if (r.isErr) { return Err(r.error); }
      results.addAll(r.value.outputPackets);
      nextTimeout = r.value.nextTimeout ?? nextTimeout;
    }

    return Ok(ProcessResult(outputPackets: results, nextTimeout: nextTimeout));
  }

  @override
  Result<ProcessResult, ProtocolError> handleTimeout(TimerToken token) {
    if (token is SctpT1InitToken) {
      if (_state == SctpState.cookieWait) { return _sendInit(); }
    }
    if (token is SctpT1CookieToken) {
      if (_state == SctpState.cookieEchoed && _cookie != null) {
        return _sendCookieEcho(_cookie!);
      }
    }
    if (token is SctpT3RtxToken) {
      return _retransmit(token.tsn);
    }
    return const Ok(ProcessResult.empty);
  }

  // ── Chunk processing ──────────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _processChunk(SctpChunk chunk) {
    switch (chunk) {
      case SctpInitChunk():    return _handleInit(chunk);
      case SctpInitAckChunk(): return _handleInitAck(chunk);
      case SctpCookieEchoChunk(): return _handleCookieEcho(chunk);
      case SctpCookieAckChunk():  return _handleCookieAck();
      case SctpDataChunk():    return _handleData(chunk);
      case SctpSackChunk():    return _handleSack(chunk);
      case SctpHeartbeatChunk(): return _handleHeartbeat(chunk);
      case SctpHeartbeatAckChunk(): return const Ok(ProcessResult.empty);
      case SctpAbortChunk():   return _handleAbort();
      case SctpShutdownChunk(): return _handleShutdown(chunk);
      case SctpShutdownAckChunk(): return _handleShutdownAck();
      case SctpShutdownCompleteChunk(): return _handleShutdownComplete();
    }
  }

  Result<ProcessResult, ProtocolError> _handleInit(SctpInitChunk init) {
    if (_state != SctpState.closed && _state != SctpState.established) {
      if (_debug) {
        stderr.writeln('[sctp] ignoring INIT in state=$_state');
      }
      return const Ok(ProcessResult.empty);
    }
    if (_debug) {
      stderr.writeln('[sctp] INIT: tag=0x${init.initiateTag.toRadixString(16)} '
          'rwnd=${init.advertisedRecvWindowCredit} '
          'os=${init.numOutboundStreams} is=${init.numInboundStreams} '
          'tsn=0x${init.initialTsn.toRadixString(16)} '
          'params=${init.parameters.map((p) => '0x${p.type.toRadixString(16)}').join(',')}');
    }
    _remoteVerificationTag = init.initiateTag;
    _remoteInitialTsn = init.initialTsn;
    _cumulativeRemoteTsn = _remoteInitialTsn - 1;
    _localVerificationTag = Csprng.randomUint32();
    _localInitialTsn = Csprng.randomUint32();
    _localTsn = _localInitialTsn;

    // Generate cookie (opaque blob)
    final cookie = Csprng.randomBytes(24);

    final ack = SctpInitAckChunk(
      initiateTag: _localVerificationTag,
      advertisedRecvWindowCredit: _defaultRwnd,
      numOutboundStreams: 1024,
      numInboundStreams: 1024,
      initialTsn: _localInitialTsn,
      cookie: cookie,
    );
    _state = SctpState.cookieWait; // server waits for COOKIE-ECHO
    return Ok(ProcessResult(outputPackets: [_buildPacket([ack])]));
  }

  Result<ProcessResult, ProtocolError> _handleInitAck(SctpInitAckChunk ack) {
    if (_state != SctpState.cookieWait) { return const Ok(ProcessResult.empty); }
    _remoteVerificationTag = ack.initiateTag;
    _remoteInitialTsn = ack.initialTsn;
    _cumulativeRemoteTsn = _remoteInitialTsn - 1;
    _cookie = ack.cookie;
    _state = SctpState.cookieEchoed;
    return _sendCookieEcho(ack.cookie);
  }

  Result<ProcessResult, ProtocolError> _sendCookieEcho(Uint8List cookie) {
    final echo = SctpCookieEchoChunk(cookie);
    final timeout = Timeout(
      at: DateTime.now().add(const Duration(milliseconds: 1000)),
      token: SctpT1CookieToken(),
    );
    return Ok(ProcessResult(
      outputPackets: [_buildPacket([echo])],
      nextTimeout: timeout,
    ));
  }

  Result<ProcessResult, ProtocolError> _handleCookieEcho(SctpCookieEchoChunk echo) {
    // Server: validate and accept
    _state = SctpState.established;
    onEstablished?.call();
    final ack = const SctpCookieAckChunk();
    return Ok(ProcessResult(outputPackets: [_buildPacket([ack])]));
  }

  Result<ProcessResult, ProtocolError> _handleCookieAck() {
    if (_state != SctpState.cookieEchoed) { return const Ok(ProcessResult.empty); }
    _state = SctpState.established;
    onEstablished?.call();
    return const Ok(ProcessResult.empty);
  }

  // Buffer for out-of-order received chunks
  final Map<int, SctpDataChunk> _recvBuffer = {};
  final Set<int> _receivedTsns = {};

  // Fragment reassembly buffer: streamId → list of chunk fragments
  final Map<int, List<SctpDataChunk>> _reassemblyBuffer = {};

  Result<ProcessResult, ProtocolError> _handleData(SctpDataChunk data) {
    final tsn = data.tsn;

    // Ignore duplicates
    if (_receivedTsns.contains(tsn)) {
      final sack = SctpSackChunk(
        cumulativeTsnAck: _cumulativeRemoteTsn,
        advertisedRecvWindowCredit: _localRwnd,
      );
      return Ok(ProcessResult(outputPackets: [_buildPacket([sack])]));
    }

    _receivedTsns.add(tsn);

    // If this is the next expected TSN, advance cumulative and deliver
    final nextExpected = (_cumulativeRemoteTsn + 1) & 0xFFFFFFFF;
    if (tsn == nextExpected) {
      _cumulativeRemoteTsn = tsn;
      _deliverOrBuffer(data);

      // Deliver any buffered chunks that are now in order
      while (true) {
        final next = (_cumulativeRemoteTsn + 1) & 0xFFFFFFFF;
        final buffered = _recvBuffer.remove(next);
        if (buffered == null) { break; }
        _cumulativeRemoteTsn = next;
        _deliverOrBuffer(buffered);
      }
    } else if (_sctpTsnGt(tsn, nextExpected)) {
      // Out-of-order: buffer it
      _recvBuffer[tsn] = data;
    }

    // Build SACK with gap ack blocks
    final gapBlocks = _computeGapBlocks();
    final sack = SctpSackChunk(
      cumulativeTsnAck: _cumulativeRemoteTsn,
      advertisedRecvWindowCredit: _localRwnd,
      gapAckBlocks: gapBlocks,
    );

    return Ok(ProcessResult(outputPackets: [_buildPacket([sack])]));
  }

  List<(int, int)> _computeGapBlocks() {
    if (_recvBuffer.isEmpty) { return const []; }
    final sorted = _recvBuffer.keys.toList()..sort((a, b) {
      if (_sctpTsnGt(a, b)) { return 1; }
      if (_sctpTsnGt(b, a)) { return -1; }
      return 0;
    });
    final blocks = <(int, int)>[];
    final base = _cumulativeRemoteTsn;
    int? blockStart;
    int? blockEnd;
    for (final tsn in sorted) {
      final offset = (tsn - base) & 0xFFFFFFFF;
      if (blockStart == null) {
        blockStart = offset;
        blockEnd = offset;
      } else if (offset == blockEnd! + 1) {
        blockEnd = offset;
      } else {
        blocks.add((blockStart, blockEnd));
        blockStart = offset;
        blockEnd = offset;
      }
    }
    if (blockStart != null) { blocks.add((blockStart, blockEnd!)); }
    return blocks;
  }

  /// Handle fragment reassembly for DATA chunks.
  /// Complete (B+E) chunks are delivered immediately.
  /// Fragmented chunks are buffered until the full message is assembled.
  void _deliverOrBuffer(SctpDataChunk chunk) {
    if (chunk.isFirst && chunk.isLast) {
      // Complete message in a single chunk — deliver immediately
      _processPayload(chunk.streamId, chunk.ppid, chunk.userData);
      return;
    }

    final sid = chunk.streamId;
    if (chunk.isFirst) {
      // Start of a new fragmented message
      _reassemblyBuffer[sid] = [chunk];
    } else {
      // Middle or end fragment
      final fragments = _reassemblyBuffer[sid];
      if (fragments == null) {
        // Orphaned fragment — skip
        return;
      }
      fragments.add(chunk);
      if (chunk.isLast) {
        // Reassemble complete message
        final totalLen = fragments.fold<int>(0, (sum, f) => sum + f.userData.length);
        final assembled = Uint8List(totalLen);
        var offset = 0;
        for (final f in fragments) {
          assembled.setRange(offset, offset + f.userData.length, f.userData);
          offset += f.userData.length;
        }
        _reassemblyBuffer.remove(sid);
        _processPayload(chunk.streamId, fragments.first.ppid, assembled);
      }
    }
  }

  void _processPayload(int streamId, int ppid, Uint8List data) {
    if (_debug) {
      stderr.writeln('[sctp] payload streamId=$streamId ppid=$ppid dataLen=${data.length}'
          ' data[0]=${data.isNotEmpty ? data[0] : -1}');
    }
    if (ppid == SctpPpid.webrtcDcep) {
      _processDcep(streamId, data);
    } else {
      final isBinary = ppid == SctpPpid.webrtcBinary || ppid == SctpPpid.webrtcBinaryEmpty;
      onData?.call(streamId, data, isBinary);
    }
  }

  void _processDcep(int streamId, Uint8List data) {
    if (data.isEmpty) { return; }
    if (data[0] == DcepMessageType.dataChannelOpen) {
      final open = DcepOpenMessage.parse(data);
      if (open == null) { return; }
      _pendingOpen[streamId] = open;
      _channelLabels[streamId] = open.label;
      final ordered = open.channelType == DcepChannelType.reliable ||
          open.channelType == DcepChannelType.partialReliableRexmit ||
          open.channelType == DcepChannelType.partialReliableTimed;
      onDataChannelOpen?.call(streamId, open.label, ordered);
      // Send ACK
      _scheduleDcepAck(streamId);
    } else if (DcepAckMessage.isDcepAck(data)) {
      final pending = _pendingOpen.remove(streamId);
      if (pending != null) {
        _channelLabels[streamId] = pending.label;
        final ordered = pending.channelType == DcepChannelType.reliable;
        onDataChannelOpen?.call(streamId, pending.label, ordered);
      }
    }
  }

  void _scheduleDcepAck(int streamId) {
    // In a real implementation this would queue an ACK DATA chunk.
    // Here we note it — the transport will pick it up on next sendData call.
    sendData(
      data: DcepAckMessage.encoded,
      streamId: streamId,
      ordered: true,
      ppid: SctpPpid.webrtcDcep,
    );
  }

  Result<ProcessResult, ProtocolError> _handleSack(SctpSackChunk sack) {
    _remoteRwnd = sack.advertisedRecvWindowCredit;
    // Remove acknowledged TSNs from retransmit queue
    final cumAck = sack.cumulativeTsnAck;
    final sizeBefore = _retransmitQueue.length;
    _retransmitQueue.removeWhere(
        (tsn, _) => !_sctpTsnGt(tsn, cumAck));
    // Reset retransmit counter when new data is acknowledged (RFC 4960 §6.3.2)
    if (_retransmitQueue.length < sizeBefore) {
      _retransmitCount = 0;
    }
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleHeartbeat(SctpHeartbeatChunk hb) {
    final ack = SctpHeartbeatAckChunk(hb.info);
    return Ok(ProcessResult(outputPackets: [_buildPacket([ack])]));
  }

  Result<ProcessResult, ProtocolError> _handleAbort() {
    _state = SctpState.closed;
    return const Ok(ProcessResult.empty);
  }

  Result<ProcessResult, ProtocolError> _handleShutdown(SctpShutdownChunk sh) {
    _state = SctpState.shutdownAckSent;
    final ack = const SctpShutdownAckChunk();
    return Ok(ProcessResult(outputPackets: [_buildPacket([ack])]));
  }

  Result<ProcessResult, ProtocolError> _handleShutdownAck() {
    _state = SctpState.closed;
    final complete = const SctpShutdownCompleteChunk();
    return Ok(ProcessResult(outputPackets: [_buildPacket([complete])]));
  }

  Result<ProcessResult, ProtocolError> _handleShutdownComplete() {
    _state = SctpState.closed;
    return const Ok(ProcessResult.empty);
  }

  // ── Init / connect ────────────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _sendInit() {
    _state = SctpState.cookieWait;
    final init = SctpInitChunk(
      initiateTag: _localVerificationTag,
      advertisedRecvWindowCredit: _defaultRwnd,
      numOutboundStreams: 1024,
      numInboundStreams: 1024,
      initialTsn: _localInitialTsn,
      parameters: const [SctpForwardTsnSupportedParameter()],
    );
    final timeout = Timeout(
      at: DateTime.now().add(const Duration(milliseconds: 1000)),
      token: SctpT1InitToken(),
    );
    return Ok(ProcessResult(
      outputPackets: [_buildPacket([init])],
      nextTimeout: timeout,
    ));
  }

  // ── Retransmit ─────────────────────────────────────────────────────────────

  Result<ProcessResult, ProtocolError> _retransmit(int tsn) {
    if (_retransmitQueue.isEmpty) { return const Ok(ProcessResult.empty); }

    if (_retransmitCount >= _maxRetransmit) {
      _state = SctpState.closed;
      return Err(const StateError('SCTP: max retransmissions exceeded'));
    }
    _retransmitCount++;
    // Retransmit ALL pending (un-ACKed) chunks, not just the triggered one.
    final packets = <OutputPacket>[];
    int? firstTsn;
    for (final entry in _retransmitQueue.entries) {
      firstTsn ??= entry.key;
      final pending = entry.value;
      final chunk = SctpDataChunk(
        flags: pending.flags,
        tsn: entry.key,
        streamId: pending.streamId,
        streamSeqNum: pending.ssn,
        ppid: pending.ppid,
        userData: pending.data,
      );
      packets.add(_buildPacket([chunk]));
    }
    // Exponential backoff per RFC 4960 §6.3.3: double RTO each retry, cap 60s
    final delayMs = (_t3RtxMs * (1 << _retransmitCount)).clamp(0, 60000);
    final timeout = Timeout(
      at: DateTime.now().add(Duration(milliseconds: delayMs)),
      token: SctpT3RtxToken(firstTsn ?? tsn),
    );
    return Ok(ProcessResult(outputPackets: packets, nextTimeout: timeout));
  }

  void _pendingData(int tsn, Uint8List data, int streamId, int ssn, int ppid, int flags) {
    _retransmitQueue[tsn] = _PendingData(
      data: data,
      streamId: streamId,
      ssn: ssn,
      ppid: ppid,
      flags: flags,
    );
  }

  // ── Packet building ───────────────────────────────────────────────────────

  OutputPacket _buildPacket(List<SctpChunk> chunks) {
    // Common header (12 bytes) + chunk bytes
    // Verification tag: for INIT use 0, otherwise remote tag
    final isInit = chunks.length == 1 && chunks[0] is SctpInitChunk;
    final vtag = isInit ? 0 : _remoteVerificationTag;

    final chunkBytes = <int>[];
    for (final c in chunks) {
      chunkBytes.addAll(c.encode());
    }

    final packet = Uint8List(12 + chunkBytes.length);
    packet[0] = (_sctpPort >> 8) & 0xFF;
    packet[1] = _sctpPort & 0xFF;
    packet[2] = (_sctpPort >> 8) & 0xFF;
    packet[3] = _sctpPort & 0xFF;
    packet[4] = (vtag >> 24) & 0xFF;
    packet[5] = (vtag >> 16) & 0xFF;
    packet[6] = (vtag >>  8) & 0xFF;
    packet[7] = vtag & 0xFF;
    // Checksum (bytes 8-11): set to 0 first, then compute CRC-32c
    packet.setRange(12, packet.length, chunkBytes);
    final crc = SctpCrc32c.compute(packet);
    packet[8]  = crc & 0xFF;
    packet[9]  = (crc >>  8) & 0xFF;
    packet[10] = (crc >> 16) & 0xFF;
    packet[11] = (crc >> 24) & 0xFF;

    return OutputPacket(data: packet, remoteIp: _remoteIp, remotePort: _remotePort);
  }

  // ── TSN comparison (RFC 4960 §6.3, 32-bit wrapped) ───────────────────────

  /// Returns true if [a] > [b] in serial number space (RFC 1982).
  static bool _sctpTsnGt(int a, int b) {
    final diff = (a - b) & 0xFFFFFFFF;
    return diff > 0 && diff < (1 << 31);
  }
}

// ignore_for_file: unused_field
enum SctpState {
  closed,
  cookieWait,
  cookieEchoed,
  established,
  shutdownPending,
  shutdownSent,
  shutdownReceived,
  shutdownAckSent,
}

class _PendingData {
  final Uint8List data;
  final int streamId;
  final int ssn;
  final int ppid;
  final int flags;
  _PendingData({
    required this.data,
    required this.streamId,
    required this.ssn,
    required this.ppid,
    required this.flags,
  });
}
