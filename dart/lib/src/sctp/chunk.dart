import 'dart:typed_data';

import '../core/byte_io.dart';

/// SCTP chunk types (RFC 4960).
abstract final class SctpChunkType {
  SctpChunkType._();
  static const int data        = 0x00;
  static const int init        = 0x01;
  static const int initAck     = 0x02;
  static const int sack        = 0x03;
  static const int heartbeat   = 0x04;
  static const int heartbeatAck= 0x05;
  static const int abort       = 0x06;
  static const int shutdown    = 0x07;
  static const int shutdownAck = 0x08;
  static const int error       = 0x09;
  static const int cookieEcho  = 0x0A;
  static const int cookieAck   = 0x0B;
  static const int shutdownComplete = 0x0E;
  static const int reconfig    = 0x82; // RFC 6525
  static const int forwardTsn  = 0xC0; // RFC 3758
}

/// SCTP common header (RFC 4960 §3.1).
final class SctpCommonHeader {
  final int srcPort;
  final int dstPort;
  final int verificationTag;
  // checksum is computed externally

  const SctpCommonHeader({
    required this.srcPort,
    required this.dstPort,
    required this.verificationTag,
  });

  static SctpCommonHeader? parse(Uint8List data) {
    if (data.length < 12) return null;
    return SctpCommonHeader(
      srcPort: readU16(data, 0),
      dstPort: readU16(data, 2),
      verificationTag: readU32(data, 4),
    );
  }
}

/// A single SCTP chunk.
sealed class SctpChunk {
  final int type;
  final int flags;
  const SctpChunk(this.type, this.flags);

  Uint8List encode();
}

final class SctpInitChunk extends SctpChunk {
  final int initiateTag;
  final int advertisedRecvWindowCredit; // a_rwnd
  final int numOutboundStreams;
  final int numInboundStreams;
  final int initialTsn;
  final List<SctpParameter> parameters;

  const SctpInitChunk({
    required this.initiateTag,
    required this.advertisedRecvWindowCredit,
    required this.numOutboundStreams,
    required this.numInboundStreams,
    required this.initialTsn,
    this.parameters = const [],
  }) : super(SctpChunkType.init, 0);

  @override
  Uint8List encode() {
    final params = _encodeParams(parameters);
    final body = Uint8List(16 + params.length);
    writeU32(body, 0, initiateTag);
    writeU32(body, 4, advertisedRecvWindowCredit);
    writeU16(body, 8, numOutboundStreams);
    writeU16(body, 10, numInboundStreams);
    writeU32(body, 12, initialTsn);
    body.setRange(16, body.length, params);
    return _wrapChunk(type, flags, body);
  }
}

final class SctpInitAckChunk extends SctpChunk {
  final int initiateTag;
  final int advertisedRecvWindowCredit;
  final int numOutboundStreams;
  final int numInboundStreams;
  final int initialTsn;
  final Uint8List cookie; // State Cookie parameter
  final List<SctpParameter> parameters;

  const SctpInitAckChunk({
    required this.initiateTag,
    required this.advertisedRecvWindowCredit,
    required this.numOutboundStreams,
    required this.numInboundStreams,
    required this.initialTsn,
    required this.cookie,
    this.parameters = const [],
  }) : super(SctpChunkType.initAck, 0);

  @override
  Uint8List encode() {
    // Include State Cookie parameter
    final cookieParam = SctpStateCookieParameter(cookie);
    final params = _encodeParams([cookieParam, ...parameters]);
    final body = Uint8List(16 + params.length);
    writeU32(body, 0, initiateTag);
    writeU32(body, 4, advertisedRecvWindowCredit);
    writeU16(body, 8, numOutboundStreams);
    writeU16(body, 10, numInboundStreams);
    writeU32(body, 12, initialTsn);
    body.setRange(16, body.length, params);
    return _wrapChunk(type, flags, body);
  }
}

final class SctpCookieEchoChunk extends SctpChunk {
  final Uint8List cookie;
  const SctpCookieEchoChunk(this.cookie) : super(SctpChunkType.cookieEcho, 0);

  @override
  Uint8List encode() => _wrapChunk(type, flags, cookie);
}

final class SctpCookieAckChunk extends SctpChunk {
  const SctpCookieAckChunk() : super(SctpChunkType.cookieAck, 0);

  @override
  Uint8List encode() => _wrapChunk(type, flags, Uint8List(0));
}

final class SctpDataChunk extends SctpChunk {
  static const int flagEnd   = 0x01;
  static const int flagBegin = 0x02;
  static const int flagUnordered = 0x04;

  final int tsn;
  final int streamId;
  final int streamSeqNum;
  final int ppid; // Payload Protocol Identifier
  final Uint8List userData;

  const SctpDataChunk({
    required int flags,
    required this.tsn,
    required this.streamId,
    required this.streamSeqNum,
    required this.ppid,
    required this.userData,
  }) : super(SctpChunkType.data, flags);

  bool get isFirst  => (flags & flagBegin) != 0;
  bool get isLast   => (flags & flagEnd) != 0;
  bool get unordered => (flags & flagUnordered) != 0;

  @override
  Uint8List encode() {
    final body = Uint8List(12 + userData.length);
    writeU32(body, 0, tsn);
    writeU16(body, 4, streamId);
    writeU16(body, 6, streamSeqNum);
    writeU32(body, 8, ppid);
    body.setRange(12, body.length, userData);
    return _wrapChunk(type, flags, body);
  }
}

final class SctpSackChunk extends SctpChunk {
  final int cumulativeTsnAck;
  final int advertisedRecvWindowCredit;
  final List<(int, int)> gapAckBlocks; // (start, end) relative to cumTsn
  final List<int> duplicateTsns;

  const SctpSackChunk({
    required this.cumulativeTsnAck,
    required this.advertisedRecvWindowCredit,
    this.gapAckBlocks = const [],
    this.duplicateTsns = const [],
  }) : super(SctpChunkType.sack, 0);

  @override
  Uint8List encode() {
    final body = Uint8List(12 + gapAckBlocks.length * 4 + duplicateTsns.length * 4);
    writeU32(body, 0, cumulativeTsnAck);
    writeU32(body, 4, advertisedRecvWindowCredit);
    writeU16(body, 8, gapAckBlocks.length);
    writeU16(body, 10, duplicateTsns.length);
    var offset = 12;
    for (final (start, end) in gapAckBlocks) {
      writeU16(body, offset, start);
      writeU16(body, offset + 2, end);
      offset += 4;
    }
    for (final tsn in duplicateTsns) {
      writeU32(body, offset, tsn);
      offset += 4;
    }
    return _wrapChunk(type, flags, body);
  }
}

final class SctpHeartbeatChunk extends SctpChunk {
  /// Raw chunk body (contains the Heartbeat Info TLV as parsed from the wire).
  final Uint8List info;
  const SctpHeartbeatChunk(this.info) : super(SctpChunkType.heartbeat, 0);

  @override
  Uint8List encode() {
    // Body already contains the Heartbeat Info TLV from the parser.
    return _wrapChunk(type, flags, info);
  }
}

final class SctpHeartbeatAckChunk extends SctpChunk {
  /// Raw chunk body (the Heartbeat Info TLV as received from the peer).
  final Uint8List info;
  const SctpHeartbeatAckChunk(this.info) : super(SctpChunkType.heartbeatAck, 0);

  @override
  Uint8List encode() {
    // Echo the body verbatim — it already contains the Heartbeat Info TLV
    // from the parsed HEARTBEAT chunk.  Do NOT re-wrap in another TLV.
    return _wrapChunk(type, flags, info);
  }
}

final class SctpAbortChunk extends SctpChunk {
  final bool tcb; // T-bit: no TCB
  const SctpAbortChunk({this.tcb = false}) : super(SctpChunkType.abort, 0);

  @override
  Uint8List encode() => _wrapChunk(type, tcb ? 0x01 : 0x00, Uint8List(0));
}

final class SctpShutdownChunk extends SctpChunk {
  final int cumulativeTsnAck;
  const SctpShutdownChunk(this.cumulativeTsnAck) : super(SctpChunkType.shutdown, 0);

  @override
  Uint8List encode() {
    final body = Uint8List(4);
    writeU32(body, 0, cumulativeTsnAck);
    return _wrapChunk(type, flags, body);
  }
}

final class SctpShutdownAckChunk extends SctpChunk {
  const SctpShutdownAckChunk() : super(SctpChunkType.shutdownAck, 0);

  @override
  Uint8List encode() => _wrapChunk(type, flags, Uint8List(0));
}

final class SctpShutdownCompleteChunk extends SctpChunk {
  const SctpShutdownCompleteChunk() : super(SctpChunkType.shutdownComplete, 0);

  @override
  Uint8List encode() => _wrapChunk(type, flags, Uint8List(0));
}

/// RE-CONFIG chunk (RFC 6525 §3.1) — carries one or two reconfiguration
/// parameters. Used by WebRTC data channels to reset (close) streams
/// (RFC 8831 §6.7).
final class SctpReconfigChunk extends SctpChunk {
  final List<SctpReconfigParameter> parameters;
  const SctpReconfigChunk(this.parameters) : super(SctpChunkType.reconfig, 0);

  @override
  Uint8List encode() =>
      _wrapChunk(type, flags, _concatBytes([for (final p in parameters) p.encode()]));
}

// ── RE-CONFIG parameters (RFC 6525 §4) ──────────────────────────────────────────

/// RE-CONFIG parameter types (RFC 6525 §4).
abstract final class SctpReconfigParamType {
  SctpReconfigParamType._();
  static const int outgoingSsnReset = 13; // 0x000D — §4.1
  static const int incomingSsnReset = 14; // 0x000E — §4.2
  static const int reconfigResponse = 16; // 0x0010 — §4.4
}

sealed class SctpReconfigParameter {
  final int type;
  const SctpReconfigParameter(this.type);

  /// The parameter value (everything after the 4-byte TLV header).
  Uint8List encodeValue();

  /// Encode as a TLV, padded to a 4-byte boundary (padding not counted in
  /// the length field, RFC 6525 §4).
  Uint8List encode() => _encodeTlv(type, encodeValue());
}

/// Outgoing SSN Reset Request Parameter (RFC 6525 §4.1) — asks the peer to
/// reset the sender's outgoing streams (i.e. the peer's incoming streams).
/// An empty [streams] list means "all streams".
final class SctpOutgoingSsnResetRequest extends SctpReconfigParameter {
  final int requestSeq;
  final int responseSeq;
  final int lastAssignedTsn;
  final List<int> streams;
  const SctpOutgoingSsnResetRequest({
    required this.requestSeq,
    required this.responseSeq,
    required this.lastAssignedTsn,
    this.streams = const [],
  }) : super(SctpReconfigParamType.outgoingSsnReset);

  @override
  Uint8List encodeValue() {
    final out = Uint8List(12 + streams.length * 2);
    writeU32(out, 0, requestSeq);
    writeU32(out, 4, responseSeq);
    writeU32(out, 8, lastAssignedTsn);
    var offset = 12;
    for (final s in streams) {
      writeU16(out, offset, s);
      offset += 2;
    }
    return out;
  }
}

/// Incoming SSN Reset Request Parameter (RFC 6525 §4.2) — asks the peer to
/// reset its outgoing streams (our incoming). An empty [streams] list means
/// "all streams".
final class SctpIncomingSsnResetRequest extends SctpReconfigParameter {
  final int requestSeq;
  final List<int> streams;
  const SctpIncomingSsnResetRequest({
    required this.requestSeq,
    this.streams = const [],
  }) : super(SctpReconfigParamType.incomingSsnReset);

  @override
  Uint8List encodeValue() {
    final out = Uint8List(4 + streams.length * 2);
    writeU32(out, 0, requestSeq);
    var offset = 4;
    for (final s in streams) {
      writeU16(out, offset, s);
      offset += 2;
    }
    return out;
  }
}

/// Re-configuration Response Parameter (RFC 6525 §4.4).
final class SctpReconfigResponse extends SctpReconfigParameter {
  // Result codes (RFC 6525 §4.4).
  static const int resultSuccessNop = 0;
  static const int resultSuccessPerformed = 1;
  static const int resultDenied = 2;
  static const int resultErrorWrongSsn = 3;
  static const int resultErrorRequestInProgress = 4;
  static const int resultErrorBadSequence = 5;
  static const int resultInProgress = 6;

  final int responseSeq;
  final int result;
  const SctpReconfigResponse({required this.responseSeq, required this.result})
      : super(SctpReconfigParamType.reconfigResponse);

  @override
  Uint8List encodeValue() {
    final out = Uint8List(8);
    writeU32(out, 0, responseSeq);
    writeU32(out, 4, result);
    return out;
  }
}

// ── Parameters ────────────────────────────────────────────────────────────────

sealed class SctpParameter {
  final int type;
  const SctpParameter(this.type);
  Uint8List encodeValue();
}

final class SctpStateCookieParameter extends SctpParameter {
  final Uint8List cookie;
  const SctpStateCookieParameter(this.cookie) : super(0x0007);
  @override
  Uint8List encodeValue() => Uint8List.fromList(cookie);
}

final class SctpSupportedExtensionsParameter extends SctpParameter {
  final List<int> chunkTypes;
  const SctpSupportedExtensionsParameter(this.chunkTypes) : super(0x8008);
  @override
  Uint8List encodeValue() => Uint8List.fromList(chunkTypes);
}

final class SctpForwardTsnSupportedParameter extends SctpParameter {
  const SctpForwardTsnSupportedParameter() : super(0xC000);
  @override
  Uint8List encodeValue() => Uint8List(0);
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// Parse chunks from a SCTP packet body (after the 12-byte common header).
List<SctpChunk> parseChunks(Uint8List data, int offset) {
  final chunks = <SctpChunk>[];
  while (offset < data.length) {
    if (data.length - offset < 4) break;
    final chunkType = data[offset];
    final chunkFlags = data[offset + 1];
    final chunkLen = (data[offset + 2] << 8) | data[offset + 3];
    if (chunkLen < 4 || offset + chunkLen > data.length) break;
    final body = data.sublist(offset + 4, offset + chunkLen);
    final chunk = _parseChunk(chunkType, chunkFlags, body);
    if (chunk != null) chunks.add(chunk);
    offset += (chunkLen + 3) & ~3; // pad to 4-byte boundary
  }
  return chunks;
}

SctpChunk? _parseChunk(int type, int flags, Uint8List body) {
  switch (type) {
    case SctpChunkType.init:
      if (body.length < 16) return null;
      return SctpInitChunk(
        initiateTag: readU32(body, 0),
        advertisedRecvWindowCredit: readU32(body, 4),
        numOutboundStreams: readU16(body, 8),
        numInboundStreams: readU16(body, 10),
        initialTsn: readU32(body, 12),
      );
    case SctpChunkType.initAck:
      if (body.length < 16) return null;
      final cookie = _extractCookie(body.sublist(16));
      return SctpInitAckChunk(
        initiateTag: readU32(body, 0),
        advertisedRecvWindowCredit: readU32(body, 4),
        numOutboundStreams: readU16(body, 8),
        numInboundStreams: readU16(body, 10),
        initialTsn: readU32(body, 12),
        cookie: cookie,
      );
    case SctpChunkType.cookieEcho:
      return SctpCookieEchoChunk(Uint8List.fromList(body));
    case SctpChunkType.cookieAck:
      return const SctpCookieAckChunk();
    case SctpChunkType.data:
      if (body.length < 12) return null;
      return SctpDataChunk(
        flags: flags,
        tsn: readU32(body, 0),
        streamId: readU16(body, 4),
        streamSeqNum: readU16(body, 6),
        ppid: readU32(body, 8),
        userData: body.sublist(12),
      );
    case SctpChunkType.sack:
      if (body.length < 12) return null;
      final numGap = readU16(body, 8);
      final numDup = readU16(body, 10);
      final gaps = <(int, int)>[];
      var offset = 12;
      for (var i = 0; i < numGap && offset + 4 <= body.length; i++) {
        gaps.add((readU16(body, offset), readU16(body, offset + 2)));
        offset += 4;
      }
      final dups = <int>[];
      for (var i = 0; i < numDup && offset + 4 <= body.length; i++) {
        dups.add(readU32(body, offset));
        offset += 4;
      }
      return SctpSackChunk(
        cumulativeTsnAck: readU32(body, 0),
        advertisedRecvWindowCredit: readU32(body, 4),
        gapAckBlocks: gaps,
        duplicateTsns: dups,
      );
    case SctpChunkType.heartbeat:
      return SctpHeartbeatChunk(Uint8List.fromList(body));
    case SctpChunkType.heartbeatAck:
      return SctpHeartbeatAckChunk(Uint8List.fromList(body));
    case SctpChunkType.abort:
      return SctpAbortChunk(tcb: (flags & 0x01) != 0);
    case SctpChunkType.shutdown:
      if (body.length < 4) return null;
      return SctpShutdownChunk(readU32(body, 0));
    case SctpChunkType.shutdownAck:
      return const SctpShutdownAckChunk();
    case SctpChunkType.shutdownComplete:
      return const SctpShutdownCompleteChunk();
    case SctpChunkType.reconfig:
      return SctpReconfigChunk(_parseReconfigParams(body));
    default:
      return null;
  }
}

List<SctpReconfigParameter> _parseReconfigParams(Uint8List body) {
  final params = <SctpReconfigParameter>[];
  var offset = 0;
  while (offset + 4 <= body.length) {
    final type = readU16(body, offset);
    final len = readU16(body, offset + 2);
    if (len < 4 || offset + len > body.length) break; // malformed
    final end = offset + len;
    switch (type) {
      case SctpReconfigParamType.outgoingSsnReset:
        if (len >= 16) {
          final streams = <int>[];
          for (var o = offset + 16; o + 2 <= end; o += 2) {
            streams.add(readU16(body, o));
          }
          params.add(SctpOutgoingSsnResetRequest(
            requestSeq: readU32(body, offset + 4),
            responseSeq: readU32(body, offset + 8),
            lastAssignedTsn: readU32(body, offset + 12),
            streams: streams,
          ));
        }
      case SctpReconfigParamType.incomingSsnReset:
        if (len >= 8) {
          final streams = <int>[];
          for (var o = offset + 8; o + 2 <= end; o += 2) {
            streams.add(readU16(body, o));
          }
          params.add(SctpIncomingSsnResetRequest(
            requestSeq: readU32(body, offset + 4),
            streams: streams,
          ));
        }
      case SctpReconfigParamType.reconfigResponse:
        if (len >= 12) {
          params.add(SctpReconfigResponse(
            responseSeq: readU32(body, offset + 4),
            result: readU32(body, offset + 8),
          ));
        }
      default:
        break; // ignore unknown reconfig parameters
    }
    offset += (len + 3) & ~3;
  }
  return params;
}

Uint8List _extractCookie(Uint8List params) {
  var offset = 0;
  while (offset + 4 <= params.length) {
    final type = readU16(params, offset);
    final len  = readU16(params, offset + 2);
    if (len < 4) break; // malformed parameter
    final end = offset + len;
    if (type == 0x0007 && end <= params.length) {
      return params.sublist(offset + 4, end);
    }
    offset += (len + 3) & ~3;
  }
  return Uint8List(0);
}

// ── Utilities ─────────────────────────────────────────────────────────────────

Uint8List _wrapChunk(int type, int flags, Uint8List body) {
  final len = 4 + body.length;
  // RFC 4960 §3.2: pad to 4-byte boundary.  Padding is NOT included in the
  // chunk length field.
  final paddedLen = (len + 3) & ~3;
  final out = Uint8List(paddedLen); // zero-filled by default
  out[0] = type;
  out[1] = flags;
  writeU16(out, 2, len);
  out.setRange(4, 4 + body.length, body);
  return out;
}

Uint8List _encodeParams(List<SctpParameter> params) =>
    _concatBytes([for (final p in params) _encodeTlv(p.type, p.encodeValue())]);

/// Encode a `type`/`length`/`value` parameter, padded to a 4-byte boundary
/// (padding is not counted in the length field — RFC 4960 §3.2.1, RFC 6525 §4).
Uint8List _encodeTlv(int type, Uint8List value) {
  final len = 4 + value.length;
  final out = Uint8List((len + 3) & ~3);
  writeU16(out, 0, type);
  writeU16(out, 2, len);
  out.setRange(4, 4 + value.length, value);
  return out;
}

Uint8List _concatBytes(List<Uint8List> parts) {
  final total = parts.fold<int>(0, (s, p) => s + p.length);
  final out = Uint8List(total);
  var offset = 0;
  for (final p in parts) {
    out.setRange(offset, offset + p.length, p);
    offset += p.length;
  }
  return out;
}
