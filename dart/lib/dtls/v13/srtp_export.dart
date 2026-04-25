import 'dart:typed_data';

import '../../crypto/hkdf.dart';
import '../../crypto/sha256.dart';

/// DTLS 1.3 SRTP keying material exporter (RFC 5764 §4.2 + RFC 8446 §7.5).
///
/// SRTP-DTLS uses the TLS-Exporter mechanism to derive the SRTP master keys
/// and salts. RFC 8446 §7.5 specifies the TLS 1.3 form:
///
///   TLS-Exporter(label, context_value, key_length) =
///       HKDF-Expand-Label(
///           Derive-Secret(exporter_master_secret, label, ""),
///           "exporter",
///           Hash(context_value),
///           key_length)
///
/// `Derive-Secret(s, l, "")` is just `HKDF-Expand-Label(s, l, Hash(""), Hash.length)`,
/// so the exporter is two HKDF-Expand-Label steps with `Hash("")` as the
/// context for the inner one.
///
/// For SRTP_AES_CM_128_HMAC_SHA1_80 the output is 60 bytes laid out as
/// `client_master_key(16) || server_master_key(16) || client_master_salt(14)
/// || server_master_salt(14)` per RFC 5764 §4.2.
abstract final class DtlsV13SrtpExport {
  DtlsV13SrtpExport._();

  /// The label RFC 5764 §4.2 specifies for SRTP keying-material extraction.
  static const String dtlsSrtpLabel = 'EXTRACTOR-dtls_srtp';

  /// Default output length (RFC 5764 §4.2 — SRTP_AES_CM_128_HMAC_SHA1_80).
  static const int srtpAes128CmHmacSha180Length = 60;

  /// Run the TLS 1.3 exporter using [exporterMasterSecret] as the
  /// `exporter_master_secret` derived during the handshake.
  static Uint8List export({
    required Uint8List exporterMasterSecret,
    String label = dtlsSrtpLabel,
    Uint8List? context,
    int length = srtpAes128CmHmacSha180Length,
  }) {
    final ctx = context ?? Uint8List(0);

    // Step 1: per-label secret =
    //   Derive-Secret(exporter_master_secret, label, "")
    // = HKDF-Expand-Label(exporter_master_secret, label, Hash(""), Hash.length)
    final perLabelSecret = Hkdf.deriveSecret(
      secret: exporterMasterSecret,
      label: label,
      transcriptHash: Sha256.hash(Uint8List(0)),
      prefix: Hkdf.dtls13Prefix,
    );

    // Step 2: out = HKDF-Expand-Label(per_label_secret,
    //                                 "exporter",
    //                                 Hash(context_value),
    //                                 length)
    return Hkdf.expandLabel(
      secret: perLabelSecret,
      label: 'exporter',
      context: Sha256.hash(ctx),
      length: length,
      prefix: Hkdf.dtls13Prefix,
    );
  }
}
