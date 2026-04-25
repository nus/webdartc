import 'dart:typed_data';

import '../../crypto/crypto_backend.dart';

/// DTLS 1.3 record protection (RFC 9147 §4).
///
/// DTLS 1.3 ciphertext records carry a "unified header" that compresses the
/// fields present in the legacy DTLS 1.2 record header. The unified header
/// always begins with a byte of the form `001CSLEE`:
///
///   bit 0..2 : fixed `001`
///   bit 3 (C): connection ID present
///   bit 4 (S): if 1, sequence number is 16 bits; if 0, 8 bits
///   bit 5 (L): if 1, length field is present (16 bits)
///   bit 6..7 (E): low 2 bits of the epoch
///
/// After the AEAD encryption, the on-the-wire sequence number bytes are
/// further protected by XOR-ing with a mask derived from the first 16 bytes
/// of the encrypted_record (RFC 9147 §4.2.3).
///
/// Records sent before encryption is established (epoch 0: ClientHello,
/// ServerHello) use the legacy DTLSPlaintext format from RFC 6347 — see
/// `lib/dtls/record.dart` for that path.
abstract final class DtlsV13Record {
  DtlsV13Record._();

  /// Build the per-record AEAD nonce (RFC 8446 §5.3 / RFC 9147 §4.2.1):
  /// the 64-bit record sequence number is left-padded with zeros to the
  /// length of [staticIv], then XORed with [staticIv].
  ///
  /// The DTLS *epoch* is **not** packed into the nonce. Per RFC 9147
  /// §4.2.1 "the epoch determines the keys" — each epoch has its own
  /// traffic secret and therefore its own [staticIv], so the epoch
  /// influences the nonce indirectly through the IV that is XORed in.
  /// (NSS / OpenSSL implement it the same way.)
  static Uint8List buildNonce(Uint8List staticIv, int seqNum) {
    if (staticIv.length != 12) {
      throw ArgumentError('static_iv must be 12 bytes');
    }
    final nonce = Uint8List.fromList(staticIv);
    // record_seq_num (8 bytes, big-endian) goes in nonce[4..11]. DTLS
    // sequence numbers are 48-bit, so the top 16 bits are always zero.
    nonce[4]  ^= (seqNum >> 56) & 0xFF;
    nonce[5]  ^= (seqNum >> 48) & 0xFF;
    nonce[6]  ^= (seqNum >> 40) & 0xFF;
    nonce[7]  ^= (seqNum >> 32) & 0xFF;
    nonce[8]  ^= (seqNum >> 24) & 0xFF;
    nonce[9]  ^= (seqNum >> 16) & 0xFF;
    nonce[10] ^= (seqNum >>  8) & 0xFF;
    nonce[11] ^=  seqNum        & 0xFF;
    return nonce;
  }

  /// Build a DTLS 1.3 ciphertext record using the C=0, S=1, L=1 unified
  /// header form (no Connection ID, 16-bit truncated seq, 16-bit length).
  ///
  /// The output layout is:
  ///
  ///   [0]      header byte = 0x2C | (epoch & 0x03)
  ///   [1..2]   truncated sequence number (low 16 bits of [seqNum])
  ///   [3..4]   length of [ciphertext]
  ///   [5..]    [ciphertext]
  ///
  /// Sequence-number encryption (RFC 9147 §4.2.3) is **not** applied here;
  /// callers must invoke [maskSequenceNumber] after AEAD encryption produces
  /// the final ciphertext.
  static Uint8List build({
    required int epoch,
    required int seqNum,
    required Uint8List ciphertext,
  }) {
    if (ciphertext.length > 0xFFFF) {
      throw ArgumentError('ciphertext too long for 16-bit length field');
    }
    final out = Uint8List(5 + ciphertext.length);
    out[0] = 0x2C | (epoch & 0x03);
    out[1] = (seqNum >> 8) & 0xFF;
    out[2] =  seqNum       & 0xFF;
    out[3] = (ciphertext.length >> 8) & 0xFF;
    out[4] =  ciphertext.length       & 0xFF;
    out.setRange(5, out.length, ciphertext);
    return out;
  }

  /// Byte offset of the first sequence-number byte for records built by
  /// [build] (header byte at [0], sequence number at [1..2]).
  static const int seqOffsetForBuild = 1;

  /// Byte offset of the first ciphertext byte for records built by [build].
  static const int ciphertextOffsetForBuild = 5;

  /// Parse a DTLS 1.3 unified-header record. Returns `null` if the input is
  /// not a valid DTLS 1.3 ciphertext record (e.g. legacy DTLSPlaintext or
  /// truncated input). Connection ID is not supported and yields `null`.
  static DtlsV13Header? parse(Uint8List packet) {
    if (packet.isEmpty) return null;
    final b = packet[0];
    // Top three bits must be `001`.
    if ((b & 0xE0) != 0x20) return null;
    final cidPresent    = (b & 0x10) != 0;
    final seq16         = (b & 0x08) != 0;
    final lengthPresent = (b & 0x04) != 0;
    final epochLow      =  b & 0x03;
    if (cidPresent) return null; // not supported

    var off = 1;
    final seqLen = seq16 ? 2 : 1;
    if (packet.length < off + seqLen) return null;
    final seqOffset = off;
    int truncatedSeq = packet[off];
    if (seq16) truncatedSeq = (truncatedSeq << 8) | packet[off + 1];
    off += seqLen;

    int? length;
    if (lengthPresent) {
      if (packet.length < off + 2) return null;
      length = (packet[off] << 8) | packet[off + 1];
      off += 2;
    }
    final ciphertextLen = length ?? packet.length - off;
    if (packet.length < off + ciphertextLen) return null;
    return DtlsV13Header(
      epochLowBits: epochLow,
      seqLen: seqLen,
      seqOffset: seqOffset,
      truncatedSeq: truncatedSeq,
      length: length,
      ciphertextOffset: off,
      ciphertextLength: ciphertextLen,
    );
  }

  /// Apply RFC 9147 §4.2.3 sequence-number masking in place.
  ///
  /// The mask is the first [seqLen] bytes of `AES-ECB(snKey, ciphertext[0..15])`.
  /// XOR is symmetric, so the same call both encrypts (sender, after AEAD)
  /// and decrypts (receiver, before AEAD).
  ///
  /// [record] is the full record (header + ciphertext); [seqOffset] points to
  /// the truncated seq bytes to be masked, [ciphertextOffset] points to the
  /// first ciphertext byte (must have at least 16 bytes available).
  static void maskSequenceNumber({
    required Uint8List record,
    required int seqOffset,
    required int seqLen,
    required int ciphertextOffset,
    required Uint8List snKey,
  }) {
    if (snKey.length != 16 && snKey.length != 32) {
      throw ArgumentError('sn_key must be 16 or 32 bytes');
    }
    if (record.length < ciphertextOffset + 16) {
      throw ArgumentError('ciphertext must be at least 16 bytes for masking');
    }
    final sample = Uint8List.fromList(
      record.sublist(ciphertextOffset, ciphertextOffset + 16),
    );
    final mask = aesCmBackend.aesEcbEncryptBlock(snKey, sample);
    for (var i = 0; i < seqLen; i++) {
      record[seqOffset + i] ^= mask[i];
    }
  }
}

/// Parsed view of a DTLS 1.3 unified header.
final class DtlsV13Header {
  /// Low 2 bits of the epoch from the header byte.
  final int epochLowBits;

  /// Number of bytes that encode the truncated sequence number (1 or 2).
  final int seqLen;

  /// Byte offset of the first truncated sequence number byte in the parsed
  /// packet — needed to reverse the mask.
  final int seqOffset;

  /// Truncated sequence number as read from the wire (still masked when
  /// returned by [DtlsV13Record.parse]; unmask before consuming).
  final int truncatedSeq;

  /// Length field (16-bit) when L=1, else null.
  final int? length;

  /// Byte offset of the first encrypted_record byte in the parsed packet.
  final int ciphertextOffset;

  /// Length of the encrypted_record in bytes.
  final int ciphertextLength;

  const DtlsV13Header({
    required this.epochLowBits,
    required this.seqLen,
    required this.seqOffset,
    required this.truncatedSeq,
    required this.length,
    required this.ciphertextOffset,
    required this.ciphertextLength,
  });
}
