import 'dart:typed_data';

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
    final epoch = _readUint16(data, offset + 3);
    final seqHi = _readUint16(data, offset + 5);
    final seqLo = _readUint32(data, offset + 7);
    final seqNum = (seqHi << 32) | seqLo;
    final length = _readUint16(data, offset + 11);
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
    out[1] = (version >> 8) & 0xFF;
    out[2] = version & 0xFF;
    out[3] = (epoch >> 8) & 0xFF;
    out[4] = epoch & 0xFF;
    // 48-bit sequence number
    out[5] = (sequenceNumber >> 40) & 0xFF;
    out[6] = (sequenceNumber >> 32) & 0xFF;
    out[7] = (sequenceNumber >> 24) & 0xFF;
    out[8] = (sequenceNumber >> 16) & 0xFF;
    out[9] = (sequenceNumber >>  8) & 0xFF;
    out[10] = sequenceNumber        & 0xFF;
    out[11] = (fragment.length >> 8) & 0xFF;
    out[12] = fragment.length & 0xFF;
    out.setRange(13, out.length, fragment);
    return out;
  }

  static int _readUint16(Uint8List d, int o) => (d[o] << 8) | d[o + 1];
  static int _readUint32(Uint8List d, int o) =>
      ((d[o] << 24) | (d[o+1] << 16) | (d[o+2] << 8) | d[o+3]) >>> 0;
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
    final length = (data[1] << 16) | (data[2] << 8) | data[3];
    final messageSeq = (data[4] << 8) | data[5];
    final fragOffset = (data[6] << 16) | (data[7] << 8) | data[8];
    final fragLen = (data[9] << 16) | (data[10] << 8) | data[11];
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
    out[1] = (length >> 16) & 0xFF;
    out[2] = (length >> 8) & 0xFF;
    out[3] = length & 0xFF;
    out[4] = (messageSeq >> 8) & 0xFF;
    out[5] = messageSeq & 0xFF;
    out[6] = (fragmentOffset >> 16) & 0xFF;
    out[7] = (fragmentOffset >>  8) & 0xFF;
    out[8] = fragmentOffset & 0xFF;
    out[9]  = (body.length >> 16) & 0xFF;
    out[10] = (body.length >>  8) & 0xFF;
    out[11] = body.length & 0xFF;
    out.setRange(12, out.length, body);
    return out;
  }
}
