import 'dart:typed_data';

/// TLS 1.3 / DTLS 1.3 handshake message format helpers (RFC 8446 §4 +
/// RFC 9147 §5). This module knows how to *describe* messages on the
/// wire — building outbound bytes, parsing inbound bytes — but leaves
/// state-machine sequencing, retransmission, and crypto to the caller.
///
/// The 12-byte DTLS handshake header (`type(1) + length(3) + msg_seq(2)
/// + frag_offset(3) + frag_length(3)`) is identical to DTLS 1.2 and is
/// added by [wrapHandshake]. Bodies are returned without that header so
/// they can also be hashed via the TLS-1.3-form transcript (which strips
/// `msg_seq` / `frag_offset` / `frag_length` — see `transcript.dart`).

/// TLS 1.3 / DTLS 1.3 handshake type IDs (RFC 8446 §4 + RFC 9147 §5).
abstract final class TlsV13HandshakeType {
  TlsV13HandshakeType._();

  static const int clientHello         = 1;
  static const int serverHello         = 2;
  static const int newSessionTicket    = 4;
  static const int endOfEarlyData      = 5;
  static const int encryptedExtensions = 8;
  static const int certificate         = 11;
  static const int certificateRequest  = 13;
  static const int certificateVerify   = 15;
  static const int finished            = 20;
  static const int keyUpdate           = 24;

  /// DTLS 1.3 only (RFC 9147 §7).
  static const int ack = 26;

  /// Synthetic message used for HelloRetryRequest transcript (RFC 8446 §4.4.1).
  static const int messageHash = 254;
}

/// Selected TLS 1.3 extension type IDs (RFC 8446 §4.2 + RFC 5764 + RFC 7301).
abstract final class TlsV13ExtensionType {
  TlsV13ExtensionType._();

  static const int serverName            = 0x0000; // RFC 6066
  static const int supportedGroups       = 0x000A; // RFC 8446
  static const int signatureAlgorithms   = 0x000D; // RFC 8446
  static const int useSrtp               = 0x000E; // RFC 5764
  static const int alpn                  = 0x0010; // RFC 7301
  static const int extendedMasterSecret  = 0x0017; // RFC 7627 (DTLS 1.2 holdover)
  static const int recordSizeLimit       = 0x001C; // RFC 8449
  static const int preSharedKey          = 0x0029; // RFC 8446
  static const int supportedVersions     = 0x002B; // RFC 8446
  static const int cookie                = 0x002C; // RFC 8446
  static const int keyShare              = 0x0033; // RFC 8446
}

/// TLS 1.3 signature schemes (RFC 8446 §4.2.3).
abstract final class TlsV13SignatureScheme {
  TlsV13SignatureScheme._();

  static const int ecdsaSecp256r1Sha256 = 0x0403;
  static const int rsaPssRsaeSha256     = 0x0804;
  static const int ed25519              = 0x0807;
}

/// TLS 1.3 named groups (RFC 8446 §4.2.7).
abstract final class TlsV13NamedGroup {
  TlsV13NamedGroup._();

  static const int secp256r1 = 0x0017;
  static const int x25519    = 0x001D;
}

/// DTLS 1.3 protocol version: `0xFEFC`. Used in `supported_versions`.
const int dtls13Version = 0xFEFC;

/// DTLS 1.2 protocol version: `0xFEFD`. Used as the legacy_version in DTLS
/// 1.3 ClientHello/ServerHello (real version negotiated in supported_versions).
const int dtls12Version = 0xFEFD;

// ─── Extension block codec ────────────────────────────────────────────────

/// One TLS extension as it appears on the wire.
final class TlsExtension {
  final int type;
  final Uint8List data;

  const TlsExtension(this.type, this.data);
}

/// Parse a TLS extensions block: `uint16 total_len || (type(2) || len(2) ||
/// data){total_len}`. Returns null if structurally invalid.
List<TlsExtension>? parseTlsExtensionsBlock(Uint8List body, int offset) {
  if (offset + 2 > body.length) return null;
  final total = (body[offset] << 8) | body[offset + 1];
  offset += 2;
  final end = offset + total;
  if (end > body.length) return null;
  final out = <TlsExtension>[];
  while (offset + 4 <= end) {
    final type = (body[offset] << 8) | body[offset + 1];
    final len  = (body[offset + 2] << 8) | body[offset + 3];
    offset += 4;
    if (offset + len > end) return null;
    out.add(TlsExtension(type, body.sublist(offset, offset + len)));
    offset += len;
  }
  if (offset != end) return null;
  return out;
}

/// Build the standard `<6..2^16-1>` extensions block from a list.
Uint8List buildTlsExtensionsBlock(List<TlsExtension> exts) {
  var dataLen = 0;
  for (final e in exts) {
    dataLen += 4 + e.data.length;
  }
  if (dataLen > 0xFFFF) {
    throw ArgumentError('extensions block exceeds 16-bit length');
  }
  final out = Uint8List(2 + dataLen);
  out[0] = (dataLen >> 8) & 0xFF;
  out[1] =  dataLen        & 0xFF;
  var off = 2;
  for (final e in exts) {
    out[off++] = (e.type >> 8) & 0xFF;
    out[off++] =  e.type        & 0xFF;
    out[off++] = (e.data.length >> 8) & 0xFF;
    out[off++] =  e.data.length        & 0xFF;
    out.setRange(off, off + e.data.length, e.data);
    off += e.data.length;
  }
  return out;
}

// ─── DTLS handshake header wrap ───────────────────────────────────────────

/// Wrap [body] in the DTLS 1.3 handshake header (12 bytes):
/// `type(1) + length(3) + msg_seq(2) + frag_offset(3) + frag_length(3)`.
/// The message is emitted as a single fragment (`fragment_offset = 0`,
/// `fragment_length = body.length`).
Uint8List wrapHandshake({
  required int msgType,
  required int msgSeq,
  required Uint8List body,
}) {
  if (body.length > 0xFFFFFF) {
    throw ArgumentError('handshake body too large for 24-bit length');
  }
  final out = Uint8List(12 + body.length);
  out[0] = msgType;
  out[1] = (body.length >> 16) & 0xFF;
  out[2] = (body.length >>  8) & 0xFF;
  out[3] =  body.length        & 0xFF;
  out[4] = (msgSeq >> 8) & 0xFF;
  out[5] =  msgSeq        & 0xFF;
  // fragment_offset = 0
  out[6] = 0; out[7] = 0; out[8] = 0;
  // fragment_length = body.length
  out[9]  = (body.length >> 16) & 0xFF;
  out[10] = (body.length >>  8) & 0xFF;
  out[11] =  body.length        & 0xFF;
  out.setRange(12, out.length, body);
  return out;
}

// ─── ClientHello parsing ──────────────────────────────────────────────────

/// Parsed ClientHello as it appears in DTLS 1.3 (the DTLS handshake header
/// must already have been stripped by the caller). Mirrors
/// `ClientHello` from RFC 8446 §4.1.2, with the DTLS-only `cookie` field.
final class ClientHelloMessage {
  final int legacyVersion;             // typically 0xFEFD (DTLS 1.2)
  final Uint8List random;              // 32 bytes
  final Uint8List legacySessionId;     // 0..32 bytes
  final Uint8List cookie;              // DTLS only — 0..255 bytes
  final List<int> cipherSuites;        // 16-bit values
  final List<int> compressionMethods;  // typically [0]
  final List<TlsExtension> extensions;

  const ClientHelloMessage({
    required this.legacyVersion,
    required this.random,
    required this.legacySessionId,
    required this.cookie,
    required this.cipherSuites,
    required this.compressionMethods,
    required this.extensions,
  });

  /// Returns the first extension matching [type], or null.
  TlsExtension? extensionByType(int type) {
    for (final e in extensions) {
      if (e.type == type) return e;
    }
    return null;
  }
}

/// Parse a ClientHello body (the bytes following the 12-byte DTLS handshake
/// header). Returns null on any structural error.
ClientHelloMessage? parseClientHello(Uint8List body) {
  if (body.length < 35) return null; // version(2) + random(32) + sid_len(1)
  final legacyVer = (body[0] << 8) | body[1];
  final random = body.sublist(2, 34);
  final sidLen = body[34];
  if (35 + sidLen > body.length) return null;
  final sid = body.sublist(35, 35 + sidLen);
  var off = 35 + sidLen;

  // DTLS-only cookie field.
  if (off >= body.length) return null;
  final cookieLen = body[off];
  off += 1;
  if (off + cookieLen > body.length) return null;
  final cookie = body.sublist(off, off + cookieLen);
  off += cookieLen;

  // cipher_suites: uint16 length + (uint16 * N).
  if (off + 2 > body.length) return null;
  final csTotal = (body[off] << 8) | body[off + 1];
  off += 2;
  if (off + csTotal > body.length || csTotal % 2 != 0 || csTotal == 0) {
    return null;
  }
  final suites = <int>[];
  for (var i = 0; i < csTotal; i += 2) {
    suites.add((body[off + i] << 8) | body[off + i + 1]);
  }
  off += csTotal;

  // compression_methods: uint8 length + bytes.
  if (off + 1 > body.length) return null;
  final cmLen = body[off];
  off += 1;
  if (off + cmLen > body.length || cmLen == 0) return null;
  final cm = <int>[];
  for (var i = 0; i < cmLen; i++) {
    cm.add(body[off + i]);
  }
  off += cmLen;

  final exts = parseTlsExtensionsBlock(body, off);
  if (exts == null) return null;

  return ClientHelloMessage(
    legacyVersion: legacyVer,
    random: random,
    legacySessionId: sid,
    cookie: cookie,
    cipherSuites: suites,
    compressionMethods: cm,
    extensions: exts,
  );
}

// ─── ServerHello build / parse ────────────────────────────────────────────

/// Build a DTLS 1.3 ServerHello body. `legacy_version` is fixed at DTLS 1.2;
/// the negotiated DTLS 1.3 version is conveyed via the [extensions] caller
/// must include (`supported_versions` carrying [dtls13Version], and
/// `key_share` for the selected group).
Uint8List buildServerHelloBody({
  required Uint8List random,
  required Uint8List legacySessionIdEcho,
  required int cipherSuite,
  required List<TlsExtension> extensions,
}) {
  if (random.length != 32) {
    throw ArgumentError('ServerHello.random must be 32 bytes');
  }
  if (legacySessionIdEcho.length > 32) {
    throw ArgumentError('legacy_session_id_echo too long');
  }
  final extBlock = buildTlsExtensionsBlock(extensions);
  final out = Uint8List(
    2 + 32 + 1 + legacySessionIdEcho.length + 2 + 1 + extBlock.length,
  );
  var off = 0;
  out[off++] = (dtls12Version >> 8) & 0xFF;
  out[off++] =  dtls12Version        & 0xFF;
  out.setRange(off, off + 32, random);
  off += 32;
  out[off++] = legacySessionIdEcho.length;
  out.setRange(off, off + legacySessionIdEcho.length, legacySessionIdEcho);
  off += legacySessionIdEcho.length;
  out[off++] = (cipherSuite >> 8) & 0xFF;
  out[off++] =  cipherSuite        & 0xFF;
  out[off++] = 0; // legacy_compression_method = null
  out.setRange(off, off + extBlock.length, extBlock);
  return out;
}

/// Parsed ServerHello (mirror of [buildServerHelloBody]) — primarily used
/// in tests for round-trip verification.
final class ServerHelloMessage {
  final int legacyVersion;
  final Uint8List random;
  final Uint8List legacySessionIdEcho;
  final int cipherSuite;
  final int legacyCompressionMethod;
  final List<TlsExtension> extensions;

  const ServerHelloMessage({
    required this.legacyVersion,
    required this.random,
    required this.legacySessionIdEcho,
    required this.cipherSuite,
    required this.legacyCompressionMethod,
    required this.extensions,
  });
}

ServerHelloMessage? parseServerHelloBody(Uint8List body) {
  if (body.length < 35) return null;
  final ver = (body[0] << 8) | body[1];
  final random = body.sublist(2, 34);
  final sidLen = body[34];
  if (35 + sidLen > body.length) return null;
  final sid = body.sublist(35, 35 + sidLen);
  var off = 35 + sidLen;
  if (off + 3 > body.length) return null;
  final cs = (body[off] << 8) | body[off + 1];
  off += 2;
  final cm = body[off];
  off += 1;
  final exts = parseTlsExtensionsBlock(body, off);
  if (exts == null) return null;
  return ServerHelloMessage(
    legacyVersion: ver,
    random: random,
    legacySessionIdEcho: sid,
    cipherSuite: cs,
    legacyCompressionMethod: cm,
    extensions: exts,
  );
}

// ─── EncryptedExtensions ──────────────────────────────────────────────────

/// `EncryptedExtensions` body (RFC 8446 §4.3.1):
/// `Extension extensions<0..2^16-1>;`
Uint8List buildEncryptedExtensionsBody(List<TlsExtension> extensions) =>
    buildTlsExtensionsBlock(extensions);

List<TlsExtension>? parseEncryptedExtensionsBody(Uint8List body) =>
    parseTlsExtensionsBlock(body, 0);

// ─── Certificate (TLS 1.3 form) ───────────────────────────────────────────

/// Build the TLS 1.3 Certificate body (RFC 8446 §4.4.2). Each entry is the
/// raw DER-encoded certificate followed by an empty per-cert extensions
/// block. The OCSP / SCT hooks RFC 8446 supports are not implemented here.
Uint8List buildCertificateBody({
  required Uint8List certificateRequestContext,
  required List<Uint8List> certDerChain,
}) {
  if (certificateRequestContext.length > 0xFF) {
    throw ArgumentError('certificate_request_context too long');
  }
  var listLen = 0;
  for (final cert in certDerChain) {
    if (cert.length > 0xFFFFFF) {
      throw ArgumentError('certificate exceeds 24-bit length');
    }
    listLen += 3 + cert.length + 2; // cert_data length + cert + empty exts
  }
  if (listLen > 0xFFFFFF) {
    throw ArgumentError('certificate_list exceeds 24-bit length');
  }
  final out = Uint8List(
    1 + certificateRequestContext.length + 3 + listLen,
  );
  var off = 0;
  out[off++] = certificateRequestContext.length;
  out.setRange(off, off + certificateRequestContext.length,
      certificateRequestContext);
  off += certificateRequestContext.length;
  out[off++] = (listLen >> 16) & 0xFF;
  out[off++] = (listLen >>  8) & 0xFF;
  out[off++] =  listLen        & 0xFF;
  for (final cert in certDerChain) {
    out[off++] = (cert.length >> 16) & 0xFF;
    out[off++] = (cert.length >>  8) & 0xFF;
    out[off++] =  cert.length        & 0xFF;
    out.setRange(off, off + cert.length, cert);
    off += cert.length;
    // empty per-cert extensions (uint16 0)
    out[off++] = 0; out[off++] = 0;
  }
  return out;
}

// ─── CertificateVerify ────────────────────────────────────────────────────

/// `CertificateVerify` body (RFC 8446 §4.4.3):
///
///   SignatureScheme algorithm;
///   opaque signature<0..2^16-1>;
Uint8List buildCertificateVerifyBody({
  required int signatureScheme,
  required Uint8List signature,
}) {
  if (signature.length > 0xFFFF) {
    throw ArgumentError('signature too long');
  }
  final out = Uint8List(2 + 2 + signature.length);
  out[0] = (signatureScheme >> 8) & 0xFF;
  out[1] =  signatureScheme        & 0xFF;
  out[2] = (signature.length >> 8) & 0xFF;
  out[3] =  signature.length        & 0xFF;
  out.setRange(4, out.length, signature);
  return out;
}

/// Bytes the CertificateVerify signature must cover, per RFC 8446 §4.4.3:
///
///   prefix = 64 * 0x20 || context_string || 0x00
///   content = prefix || transcript_hash
///
/// where `context_string` is `"TLS 1.3, server CertificateVerify"` for the
/// server's signature and `"TLS 1.3, client CertificateVerify"` for the
/// client's. The resulting byte string is what gets passed to the signing
/// key (no further hashing here — the signing primitive may hash itself).
Uint8List certificateVerifySignedContent({
  required Uint8List transcriptHash,
  required bool isServer,
}) {
  final ctx = isServer
      ? 'TLS 1.3, server CertificateVerify'
      : 'TLS 1.3, client CertificateVerify';
  final out = Uint8List(64 + ctx.length + 1 + transcriptHash.length);
  for (var i = 0; i < 64; i++) {
    out[i] = 0x20;
  }
  for (var i = 0; i < ctx.length; i++) {
    out[64 + i] = ctx.codeUnitAt(i);
  }
  out[64 + ctx.length] = 0x00;
  out.setRange(64 + ctx.length + 1, out.length, transcriptHash);
  return out;
}

// ─── Finished ─────────────────────────────────────────────────────────────

/// `Finished` body (RFC 8446 §4.4.4): just the `verify_data`. The caller
/// computes `HMAC-Hash(finished_key, transcript_hash)`.
Uint8List buildFinishedBody(Uint8List verifyData) =>
    Uint8List.fromList(verifyData);

// ─── Extension data builders / parsers ────────────────────────────────────

/// `supported_versions` extension data for ServerHello (RFC 8446 §4.2.1):
/// a single 2-byte selected_version.
Uint8List buildServerHelloSupportedVersionsExtData(int version) =>
    Uint8List.fromList([(version >> 8) & 0xFF, version & 0xFF]);

/// `supported_versions` extension data for ClientHello (RFC 8446 §4.2.1):
///   uint8 list_length || (uint16 version){list_length}
List<int>? parseClientHelloSupportedVersionsExtData(Uint8List data) {
  if (data.isEmpty) return null;
  final total = data[0];
  if (total + 1 != data.length || total % 2 != 0 || total == 0) return null;
  final out = <int>[];
  for (var i = 0; i < total; i += 2) {
    out.add((data[1 + i] << 8) | data[2 + i]);
  }
  return out;
}

/// One `KeyShareEntry` (RFC 8446 §4.2.8): named group + opaque public key.
final class KeyShareEntry {
  final int group;
  final Uint8List keyExchange;
  const KeyShareEntry({required this.group, required this.keyExchange});
}

/// `key_share` extension data for ServerHello: a single KeyShareEntry.
Uint8List buildServerHelloKeyShareExtData({
  required int namedGroup,
  required Uint8List keyExchange,
}) {
  if (keyExchange.length > 0xFFFF) {
    throw ArgumentError('key_exchange too long');
  }
  final out = Uint8List(4 + keyExchange.length);
  out[0] = (namedGroup >> 8) & 0xFF;
  out[1] =  namedGroup        & 0xFF;
  out[2] = (keyExchange.length >> 8) & 0xFF;
  out[3] =  keyExchange.length        & 0xFF;
  out.setRange(4, out.length, keyExchange);
  return out;
}

/// `key_share` extension data for ClientHello: list of KeyShareEntry.
List<KeyShareEntry>? parseClientHelloKeyShareExtData(Uint8List data) {
  if (data.length < 2) return null;
  final total = (data[0] << 8) | data[1];
  if (2 + total != data.length) return null;
  var off = 2;
  final out = <KeyShareEntry>[];
  while (off + 4 <= data.length) {
    final group = (data[off] << 8) | data[off + 1];
    final len   = (data[off + 2] << 8) | data[off + 3];
    off += 4;
    if (off + len > data.length) return null;
    out.add(KeyShareEntry(
      group: group,
      keyExchange: data.sublist(off, off + len),
    ));
    off += len;
  }
  if (off != data.length) return null;
  return out;
}

/// Parse the `use_srtp` extension data offered in a ClientHello (RFC 5764 §4.1.1):
///
///   struct {
///     SRTPProtectionProfile profiles<2..2^16-1>;
///     opaque srtp_mki<0..255>;
///   } UseSRTPData;
///
/// Returns the list of 16-bit profile IDs offered by the client, or null
/// when the wire bytes are structurally invalid. The MKI field is checked
/// for size but its bytes are otherwise ignored.
List<int>? parseUseSrtpExtData(Uint8List data) {
  if (data.length < 3) return null;
  final profilesLen = (data[0] << 8) | data[1];
  if (profilesLen == 0 || profilesLen % 2 != 0) return null;
  if (2 + profilesLen > data.length) return null;
  final mkiOffset = 2 + profilesLen;
  if (mkiOffset >= data.length) return null;
  final mkiLen = data[mkiOffset];
  if (mkiOffset + 1 + mkiLen != data.length) return null;
  final out = <int>[];
  for (var i = 0; i < profilesLen; i += 2) {
    out.add((data[2 + i] << 8) | data[3 + i]);
  }
  return out;
}

/// Build the `use_srtp` extension data the server echoes (RFC 5764 §4.1.1):
/// a list containing exactly one selected profile, followed by an empty MKI.
Uint8List buildUseSrtpExtData(int selectedProfile) {
  return Uint8List.fromList([
    0x00, 0x02, // profiles list length = 2 (one 16-bit profile)
    (selectedProfile >> 8) & 0xFF, selectedProfile & 0xFF,
    0x00, // empty MKI
  ]);
}

/// `signature_algorithms` extension data: list of 2-byte SignatureScheme
/// values, prefixed by a 2-byte total length.
List<int>? parseSignatureAlgorithmsExtData(Uint8List data) {
  if (data.length < 2) return null;
  final total = (data[0] << 8) | data[1];
  if (2 + total != data.length || total % 2 != 0 || total == 0) return null;
  final out = <int>[];
  for (var i = 0; i < total; i += 2) {
    out.add((data[2 + i] << 8) | data[3 + i]);
  }
  return out;
}
