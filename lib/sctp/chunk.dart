import 'dart:typed_data';

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
      srcPort: _u16(data, 0),
      dstPort: _u16(data, 2),
      verificationTag: _u32(data, 4),
    );
  }

  static int _u16(Uint8List d, int o) => (d[o] << 8) | d[o + 1];
  static int _u32(Uint8List d, int o) =>
      ((d[o] << 24) | (d[o+1] << 16) | (d[o+2] << 8) | d[o+3]) >>> 0;
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
    _writeU32(body, 0, initiateTag);
    _writeU32(body, 4, advertisedRecvWindowCredit);
    _writeU16(body, 8, numOutboundStreams);
    _writeU16(body, 10, numInboundStreams);
    _writeU32(body, 12, initialTsn);
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
    _writeU32(body, 0, initiateTag);
    _writeU32(body, 4, advertisedRecvWindowCredit);
    _writeU16(body, 8, numOutboundStreams);
    _writeU16(body, 10, numInboundStreams);
    _writeU32(body, 12, initialTsn);
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
    _writeU32(body, 0, tsn);
    _writeU16(body, 4, streamId);
    _writeU16(body, 6, streamSeqNum);
    _writeU32(body, 8, ppid);
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
    _writeU32(body, 0, cumulativeTsnAck);
    _writeU32(body, 4, advertisedRecvWindowCredit);
    _writeU16(body, 8, gapAckBlocks.length);
    _writeU16(body, 10, duplicateTsns.length);
    var offset = 12;
    for (final (start, end) in gapAckBlocks) {
      _writeU16(body, offset, start);
      _writeU16(body, offset + 2, end);
      offset += 4;
    }
    for (final tsn in duplicateTsns) {
      _writeU32(body, offset, tsn);
      offset += 4;
    }
    return _wrapChunk(type, flags, body);
  }
}

final class SctpHeartbeatChunk extends SctpChunk {
  final Uint8List info;
  const SctpHeartbeatChunk(this.info) : super(SctpChunkType.heartbeat, 0);

  @override
  Uint8List encode() {
    // Heartbeat Info parameter (type=0x0001)
    final param = Uint8List(4 + info.length);
    param[0] = 0x00; param[1] = 0x01;
    param[2] = ((info.length + 4) >> 8) & 0xFF;
    param[3] = (info.length + 4) & 0xFF;
    param.setRange(4, param.length, info);
    return _wrapChunk(type, flags, param);
  }
}

final class SctpHeartbeatAckChunk extends SctpChunk {
  final Uint8List info;
  const SctpHeartbeatAckChunk(this.info) : super(SctpChunkType.heartbeatAck, 0);

  @override
  Uint8List encode() {
    final param = Uint8List(4 + info.length);
    param[0] = 0x00; param[1] = 0x01;
    param[2] = ((info.length + 4) >> 8) & 0xFF;
    param[3] = (info.length + 4) & 0xFF;
    param.setRange(4, param.length, info);
    return _wrapChunk(type, flags, param);
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
    _writeU32(body, 0, cumulativeTsnAck);
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
        initiateTag: _u32(body, 0),
        advertisedRecvWindowCredit: _u32(body, 4),
        numOutboundStreams: _u16(body, 8),
        numInboundStreams: _u16(body, 10),
        initialTsn: _u32(body, 12),
      );
    case SctpChunkType.initAck:
      if (body.length < 16) return null;
      final cookie = _extractCookie(body.sublist(16));
      return SctpInitAckChunk(
        initiateTag: _u32(body, 0),
        advertisedRecvWindowCredit: _u32(body, 4),
        numOutboundStreams: _u16(body, 8),
        numInboundStreams: _u16(body, 10),
        initialTsn: _u32(body, 12),
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
        tsn: _u32(body, 0),
        streamId: _u16(body, 4),
        streamSeqNum: _u16(body, 6),
        ppid: _u32(body, 8),
        userData: body.sublist(12),
      );
    case SctpChunkType.sack:
      if (body.length < 12) return null;
      final numGap = _u16(body, 8);
      final numDup = _u16(body, 10);
      final gaps = <(int, int)>[];
      var offset = 12;
      for (var i = 0; i < numGap && offset + 4 <= body.length; i++) {
        gaps.add((_u16(body, offset), _u16(body, offset + 2)));
        offset += 4;
      }
      final dups = <int>[];
      for (var i = 0; i < numDup && offset + 4 <= body.length; i++) {
        dups.add(_u32(body, offset));
        offset += 4;
      }
      return SctpSackChunk(
        cumulativeTsnAck: _u32(body, 0),
        advertisedRecvWindowCredit: _u32(body, 4),
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
      return SctpShutdownChunk(_u32(body, 0));
    case SctpChunkType.shutdownAck:
      return const SctpShutdownAckChunk();
    case SctpChunkType.shutdownComplete:
      return const SctpShutdownCompleteChunk();
    default:
      return null;
  }
}

Uint8List _extractCookie(Uint8List params) {
  var offset = 0;
  while (offset + 4 <= params.length) {
    final type = _u16(params, offset);
    final len  = _u16(params, offset + 2);
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
  out[2] = (len >> 8) & 0xFF;
  out[3] = len & 0xFF;
  out.setRange(4, 4 + body.length, body);
  return out;
}

Uint8List _encodeParams(List<SctpParameter> params) {
  final parts = <Uint8List>[];
  for (final p in params) {
    final val = p.encodeValue();
    final len = 4 + val.length;
    final padded = (len + 3) & ~3;
    final out = Uint8List(padded);
    out[0] = (p.type >> 8) & 0xFF;
    out[1] = p.type & 0xFF;
    out[2] = (len >> 8) & 0xFF;
    out[3] = len & 0xFF;
    out.setRange(4, 4 + val.length, val);
    parts.add(out);
  }
  final total = parts.fold(0, (s, p) => s + p.length);
  final result = Uint8List(total);
  var offset = 0;
  for (final p in parts) {
    result.setRange(offset, offset + p.length, p);
    offset += p.length;
  }
  return result;
}

void _writeU16(Uint8List d, int o, int v) {
  d[o] = (v >> 8) & 0xFF;
  d[o + 1] = v & 0xFF;
}

void _writeU32(Uint8List d, int o, int v) {
  d[o] = (v >> 24) & 0xFF;
  d[o + 1] = (v >> 16) & 0xFF;
  d[o + 2] = (v >>  8) & 0xFF;
  d[o + 3] = v & 0xFF;
}

int _u16(Uint8List d, int o) => (d[o] << 8) | d[o + 1];
int _u32(Uint8List d, int o) =>
    ((d[o] << 24) | (d[o+1] << 16) | (d[o+2] << 8) | d[o+3]) >>> 0;
