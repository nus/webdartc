/// Big-endian byte packing/unpacking shared by all protocol codecs
/// (RTP/RTCP, SRTP, SCTP, STUN, DTLS).
///
/// Two styles are provided:
///
/// - Top-level [readU16]/[writeU32]-style functions for random-access
///   reads/writes at an explicit offset — direct replacements for the
///   per-module `_u16`/`_writeU32` helpers they consolidate.
/// - Offset-advancing [ByteReader]/[ByteWriter] for sequential codecs.
///
/// Bounds handling follows the existing parser contract: callers validate
/// lengths first (`if (data.length < n) return null;` / [ByteReader.remaining]),
/// then read. Out-of-range access surfaces as the usual [RangeError] from
/// list indexing rather than a softer failure.
library;

import 'dart:typed_data';

// ── Random-access reads ───────────────────────────────────────────────────

int readU16(Uint8List d, int o) => (d[o] << 8) | d[o + 1];

int readU24(Uint8List d, int o) => (d[o] << 16) | (d[o + 1] << 8) | d[o + 2];

int readU32(Uint8List d, int o) =>
    ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;

/// 48-bit read (e.g. the DTLS record sequence number).
int readU48(Uint8List d, int o) => (readU16(d, o) << 32) | readU32(d, o + 2);

/// 64-bit read. Values ≥ 2^63 wrap into Dart's signed int; wire values in
/// this library (ICE tiebreakers, DTLS record numbers) stay well below that.
int readU64(Uint8List d, int o) => (readU32(d, o) << 32) | readU32(d, o + 4);

// ── Random-access writes ──────────────────────────────────────────────────

void writeU16(Uint8List d, int o, int v) {
  d[o] = (v >> 8) & 0xFF;
  d[o + 1] = v & 0xFF;
}

void writeU24(Uint8List d, int o, int v) {
  d[o] = (v >> 16) & 0xFF;
  d[o + 1] = (v >> 8) & 0xFF;
  d[o + 2] = v & 0xFF;
}

void writeU32(Uint8List d, int o, int v) {
  d[o] = (v >> 24) & 0xFF;
  d[o + 1] = (v >> 16) & 0xFF;
  d[o + 2] = (v >> 8) & 0xFF;
  d[o + 3] = v & 0xFF;
}

/// 48-bit write (e.g. the DTLS record sequence number).
void writeU48(Uint8List d, int o, int v) {
  writeU16(d, o, (v >> 32) & 0xFFFF);
  writeU32(d, o + 2, v & 0xFFFFFFFF);
}

void writeU64(Uint8List d, int o, int v) {
  writeU32(d, o, v >>> 32);
  writeU32(d, o + 4, v & 0xFFFFFFFF);
}

// Tear-off aliases so ByteReader's methods can call the top-level readers
// their own names shadow.
const _u16 = readU16;
const _u24 = readU24;
const _u32 = readU32;
const _u48 = readU48;
const _u64 = readU64;

// ── Sequential reader ─────────────────────────────────────────────────────

/// Big-endian reader that advances an internal offset.
///
/// Reads do not bounds-check beyond list indexing; check [remaining] (or
/// [canRead]) first, matching the length-check-then-read pattern used by
/// the parsers in this library.
final class ByteReader {
  final Uint8List _data;
  int _offset;

  ByteReader(this._data, [this._offset = 0]);

  /// Current read position.
  int get offset => _offset;

  /// Bytes left to read.
  int get remaining => _data.length - _offset;

  /// Whether [n] more bytes can be read.
  bool canRead(int n) => remaining >= n;

  int readU8() => _data[_offset++];

  int readU16() {
    final v = _u16(_data, _offset);
    _offset += 2;
    return v;
  }

  int readU24() {
    final v = _u24(_data, _offset);
    _offset += 3;
    return v;
  }

  int readU32() {
    final v = _u32(_data, _offset);
    _offset += 4;
    return v;
  }

  int readU48() {
    final v = _u48(_data, _offset);
    _offset += 6;
    return v;
  }

  int readU64() {
    final v = _u64(_data, _offset);
    _offset += 8;
    return v;
  }

  /// Reads [n] bytes as a copy (matching the `sublist` semantics of the
  /// parsers this replaces).
  Uint8List readBytes(int n) {
    final v = _data.sublist(_offset, _offset + n);
    _offset += n;
    return v;
  }

  /// Advances past [n] bytes without reading them.
  void skip(int n) {
    _offset += n;
  }
}

// ── Sequential writer ─────────────────────────────────────────────────────

/// Big-endian writer that appends to a growable buffer.
final class ByteWriter {
  final BytesBuilder _builder = BytesBuilder(copy: true);

  /// Bytes written so far.
  int get length => _builder.length;

  void writeU8(int v) => _builder.addByte(v & 0xFF);

  void writeU16(int v) {
    _builder.addByte((v >> 8) & 0xFF);
    _builder.addByte(v & 0xFF);
  }

  void writeU24(int v) {
    _builder.addByte((v >> 16) & 0xFF);
    _builder.addByte((v >> 8) & 0xFF);
    _builder.addByte(v & 0xFF);
  }

  void writeU32(int v) {
    _builder.addByte((v >> 24) & 0xFF);
    _builder.addByte((v >> 16) & 0xFF);
    _builder.addByte((v >> 8) & 0xFF);
    _builder.addByte(v & 0xFF);
  }

  void writeU48(int v) {
    writeU16((v >> 32) & 0xFFFF);
    writeU32(v & 0xFFFFFFFF);
  }

  void writeU64(int v) {
    writeU32(v >>> 32);
    writeU32(v & 0xFFFFFFFF);
  }

  void writeBytes(List<int> bytes) => _builder.add(bytes);

  /// Returns everything written. The writer must not be reused afterwards.
  Uint8List takeBytes() => _builder.takeBytes();
}
