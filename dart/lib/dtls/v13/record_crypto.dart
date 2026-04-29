import 'dart:typed_data';

import '../../crypto/aes_gcm.dart';
import '../../crypto/chacha20_poly1305.dart';
import 'cipher_suite.dart';
import 'key_schedule.dart';
import 'record.dart';

/// DTLS 1.3 record-layer protection (RFC 9147 §4 + RFC 8446 §5.2).
///
/// This layer composes the lower-level pieces into encrypt / decrypt of a
/// full on-the-wire DTLSCiphertext record:
///
///   * [TrafficKeys] (write_key, write_iv, sn_key) — see `key_schedule.dart`.
///   * The unified-header build/parse and sequence-number masking from
///     `record.dart`.
///   * The negotiated AEAD primitive — AES-128-GCM (`TLS_AES_128_GCM_SHA256`,
///     0x1301) or ChaCha20-Poly1305 (`TLS_CHACHA20_POLY1305_SHA256`, 0x1303).
///
/// Records always use the C=0, S=1, L=1 unified-header variant produced by
/// [DtlsV13Record.build] (no Connection ID, 16-bit truncated sequence,
/// 16-bit length field). The AEAD output for both supported suites is
/// `content || content_type` of plaintext plus a 16-byte tag.
abstract final class DtlsV13RecordCrypto {
  DtlsV13RecordCrypto._();

  /// AEAD authentication tag length — 16 bytes for both AES-GCM and
  /// ChaCha20-Poly1305 (RFC 8446 §B.4).
  static const int _tagLength = 16;

  /// Encrypt [content] into a DTLS 1.3 ciphertext record.
  ///
  /// The DTLSInnerPlaintext is `content || contentType` with no padding.
  /// The AEAD additional_data is the unified header carrying the *plaintext*
  /// sequence number (RFC 9147 §4.2.3); after encryption the header's
  /// sequence-number bytes are XORed with the sn-mask in place so the
  /// returned record matches the on-the-wire form.
  static Uint8List encrypt({
    required int contentType,
    required Uint8List content,
    required int epoch,
    required int seqNum,
    required TrafficKeys keys,
    TlsV13CipherSuite cipherSuite = TlsV13CipherSuite.aes128GcmSha256,
  }) {
    final ctLen = content.length + 1 + _tagLength;
    if (ctLen > 0xFFFF) {
      throw ArgumentError('record exceeds 16-bit length field');
    }

    final inner = Uint8List(content.length + 1);
    inner.setRange(0, content.length, content);
    inner[content.length] = contentType;

    // Build the on-the-wire record with the *plaintext* sequence number;
    // this initial form is what the AEAD AAD covers (RFC 9147 §4.2.3).
    final record = Uint8List(5 + ctLen);
    record[0] = 0x2C | (epoch & 0x03);
    record[1] = (seqNum >> 8) & 0xFF;
    record[2] =  seqNum       & 0xFF;
    record[3] = (ctLen >> 8) & 0xFF;
    record[4] =  ctLen       & 0xFF;

    final aad = Uint8List.fromList(record.sublist(0, 5));
    final nonce = DtlsV13Record.buildNonce(keys.writeIv, seqNum);
    final useChaCha20 = cipherSuite.id == TlsV13CipherSuite.chacha20Poly1305Sha256.id;
    final Uint8List ciphertext;
    final Uint8List tag;
    if (useChaCha20) {
      final aead = ChaCha20Poly1305.encrypt(keys.writeKey, nonce, inner, aad: aad);
      ciphertext = aead.ciphertext;
      tag = aead.tag;
    } else {
      final aead = AesGcm.encrypt(keys.writeKey, nonce, inner, aad: aad);
      ciphertext = aead.ciphertext;
      tag = aead.tag;
    }
    record.setRange(5, 5 + inner.length, ciphertext);
    record.setRange(5 + inner.length, record.length, tag);

    DtlsV13Record.maskSequenceNumber(
      record: record,
      seqOffset: DtlsV13Record.seqOffsetForBuild,
      seqLen: 2,
      ciphertextOffset: DtlsV13Record.ciphertextOffsetForBuild,
      snKey: keys.snKey,
      useChaCha20: useChaCha20,
    );

    return record;
  }

  /// Decrypt a DTLS 1.3 ciphertext record.
  ///
  /// Returns `null` for any structural problem or AEAD authentication
  /// failure — DTLS treats these uniformly as silently dropped records.
  ///
  /// [epoch] is the full epoch the caller selected when picking [keys];
  /// the header's low-2-bit epoch is verified to match.
  ///
  /// [seqHi32] is the top 32 bits of the full 48-bit sequence number; the
  /// wire only carries the low 16 bits when S=1 (the form produced by
  /// [encrypt]). Phase 1 callers can pass 0 — handshake and initial
  /// application data both stay well within 2^16 records.
  static DtlsV13DecryptResult? decrypt({
    required Uint8List record,
    required TrafficKeys keys,
    required int epoch,
    int seqHi32 = 0,
    TlsV13CipherSuite cipherSuite = TlsV13CipherSuite.aes128GcmSha256,
  }) {
    final hdr = DtlsV13Record.parse(record);
    if (hdr == null) return null;
    if (hdr.seqLen != 2) return null; // we only emit S=1 for now
    if (hdr.epochLowBits != (epoch & 0x03)) return null;

    final ctLen = hdr.ciphertextLength;
    if (ctLen < _tagLength + 1) return null; // need at least content_type + tag

    final useChaCha20 = cipherSuite.id == TlsV13CipherSuite.chacha20Poly1305Sha256.id;

    // Copy so we don't mutate the caller's bytes when unmasking the seq.
    final work = Uint8List.fromList(record);
    DtlsV13Record.maskSequenceNumber(
      record: work,
      seqOffset: hdr.seqOffset,
      seqLen: hdr.seqLen,
      ciphertextOffset: hdr.ciphertextOffset,
      snKey: keys.snKey,
      useChaCha20: useChaCha20,
    );

    final seqLo16 = (work[hdr.seqOffset] << 8) | work[hdr.seqOffset + 1];
    final fullSeq = (seqHi32 << 16) | seqLo16;

    // AAD covers the unified header with the recovered plaintext seq —
    // i.e., the form the sender used during encryption.
    final aad = Uint8List.fromList(work.sublist(0, hdr.ciphertextOffset));

    final cipherStart = hdr.ciphertextOffset;
    final cipherEnd = cipherStart + ctLen - _tagLength;
    final ct = Uint8List.fromList(work.sublist(cipherStart, cipherEnd));
    final tag = Uint8List.fromList(
      work.sublist(cipherEnd, cipherStart + ctLen),
    );

    final nonce = DtlsV13Record.buildNonce(keys.writeIv, fullSeq);
    final inner = useChaCha20
        ? ChaCha20Poly1305.decrypt(keys.writeKey, nonce, ct, tag, aad: aad)
        : AesGcm.decrypt(keys.writeKey, nonce, ct, tag, aad: aad);
    if (inner == null) return null;

    // DTLSInnerPlaintext = content || ContentType || zeros[*]
    // Strip trailing zero padding and read the content type.
    var typeIdx = inner.length - 1;
    while (typeIdx >= 0 && inner[typeIdx] == 0) {
      typeIdx--;
    }
    if (typeIdx < 0) return null; // all-zero plaintext is malformed.

    return DtlsV13DecryptResult(
      contentType: inner[typeIdx],
      content: Uint8List.fromList(inner.sublist(0, typeIdx)),
      seqNum: fullSeq,
    );
  }
}

/// Result of a successful [DtlsV13RecordCrypto.decrypt].
final class DtlsV13DecryptResult {
  /// Inner ContentType byte (handshake=22, application_data=23, alert=21).
  final int contentType;

  /// Decrypted inner content with trailing ContentType + padding stripped.
  final Uint8List content;

  /// Full 48-bit sequence number recovered from the record.
  final int seqNum;

  const DtlsV13DecryptResult({
    required this.contentType,
    required this.content,
    required this.seqNum,
  });
}
