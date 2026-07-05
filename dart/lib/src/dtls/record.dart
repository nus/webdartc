import 'dart:typed_data';

import '../core/byte_io.dart';

/// DTLS content types (RFC 6347 §4.1 + RFC 9147 §4.1).
abstract final class DtlsContentType {
  DtlsContentType._();
  static const int changeCipherSpec = 20;
  static const int alert            = 21;
  static const int handshake        = 22;
  static const int applicationData  = 23;
  /// DTLS 1.3 only (RFC 9147 §7.1).
  static const int ack              = 26;
}

/// DTLS 1.2 version bytes.
const int dtls12VersionMajor = 0xFE;
const int dtls12VersionMinor = 0xFD;

/// DTLS record layer header (RFC 6347 §4.1).
final class DtlsRecord {
  final int contentType;
  final int version;   // 0xFEFD for DTLS 1.2
  final int epoch;
  final int sequenceNumber; // 48-bit
  final Uint8List fragment;

  const DtlsRecord({
    required this.contentType,
    required this.version,
    required this.epoch,
    required this.sequenceNumber,
    required this.fragment,
  });

  int get length => fragment.length;

  static DtlsRecord? parse(Uint8List data, int offset) {
    if (data.length - offset < 13) return null;
    final contentType = data[offset];
    final major = data[offset + 1];
    final minor = data[offset + 2];
    final version = (major << 8) | minor;
    final epoch = readU16(data, offset + 3);
    final seqNum = readU48(data, offset + 5);
    final length = readU16(data, offset + 11);
    if (data.length - offset - 13 < length) return null;
    final fragment = data.sublist(offset + 13, offset + 13 + length);
    return DtlsRecord(
      contentType: contentType,
      version: version,
      epoch: epoch,
      sequenceNumber: seqNum,
      fragment: fragment,
    );
  }

  Uint8List encode() {
    final out = Uint8List(13 + fragment.length);
    out[0] = contentType;
    writeU16(out, 1, version);
    writeU16(out, 3, epoch);
    writeU48(out, 5, sequenceNumber);
    writeU16(out, 11, fragment.length);
    out.setRange(13, out.length, fragment);
    return out;
  }
}

/// DTLS handshake message types (RFC 6347 §4.2.2).
abstract final class DtlsHandshakeType {
  DtlsHandshakeType._();
  static const int helloRequest       =  0;
  static const int clientHello        =  1;
  static const int serverHello        =  2;
  static const int helloVerifyRequest =  3;
  static const int certificate        = 11;
  static const int serverKeyExchange  = 12;
  static const int certificateRequest = 13;
  static const int serverHelloDone    = 14;
  static const int certificateVerify  = 15;
  static const int clientKeyExchange  = 16;
  static const int finished           = 20;
}

/// DTLS handshake header (RFC 6347 §4.2.2).
final class DtlsHandshakeHeader {
  final int msgType;
  final int length;        // 24-bit
  final int messageSeq;   // 16-bit
  final int fragmentOffset; // 24-bit
  final int fragmentLength; // 24-bit
  final Uint8List body;

  const DtlsHandshakeHeader({
    required this.msgType,
    required this.length,
    required this.messageSeq,
    required this.fragmentOffset,
    required this.fragmentLength,
    required this.body,
  });

  static DtlsHandshakeHeader? parse(Uint8List data) {
    if (data.length < 12) return null;
    final msgType = data[0];
    final length = readU24(data, 1);
    final messageSeq = readU16(data, 4);
    final fragOffset = readU24(data, 6);
    final fragLen = readU24(data, 9);
    if (data.length < 12 + fragLen) return null;
    final body = data.sublist(12, 12 + fragLen);
    return DtlsHandshakeHeader(
      msgType: msgType,
      length: length,
      messageSeq: messageSeq,
      fragmentOffset: fragOffset,
      fragmentLength: fragLen,
      body: body,
    );
  }

  Uint8List encode() {
    final out = Uint8List(12 + body.length);
    out[0] = msgType;
    writeU24(out, 1, length);
    writeU16(out, 4, messageSeq);
    writeU24(out, 6, fragmentOffset);
    writeU24(out, 9, body.length);
    out.setRange(12, out.length, body);
    return out;
  }
}
