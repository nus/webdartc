import 'dart:convert';
import 'dart:typed_data';

import '../../crypto/hmac_sha256.dart';
import '../../crypto/sha256.dart';

/// Stateless DTLS 1.3 cookie (RFC 9147 §5.1, RFC 8446 §4.2.2).
///
/// The HelloRetryRequest cookie lets a server resist resource-exhaustion
/// attacks by deferring per-connection state until the client has proven
/// it can receive at the source address it claims (return-routability).
/// The cookie is opaque to the client; the server must be able to verify
/// it without keeping per-client state, so its bytes encode everything
/// needed to recover the binding:
///
/// ```
/// cookie = version(1)            // 0x01 — wire-format version
///       || transcriptHashCh1(32) // SHA-256 of the original ClientHello
///       || tag(32)               // HMAC-SHA256(macKey, hmac_input)
///
/// hmac_input = version || transcriptHashCh1
///           || endpoint_id        // utf-8 "ip:port"
/// ```
///
/// `transcriptHashCh1` is included so the server can reconstruct the
/// `synthetic_message_hash || HelloRetryRequest` transcript in
/// CH2 processing without retaining CH1 itself (RFC 8446 §4.4.1). The
/// `endpoint_id` binding rejects replays from a different transport
/// address. The HMAC tag prevents forgery; the only persistent server
/// secret is the `macKey`.
abstract final class DtlsV13Cookie {
  DtlsV13Cookie._();

  /// Current wire-format version. The first byte of every cookie carries
  /// this value; future formats can be added without breaking old peers.
  static const int versionByte = 0x01;

  /// Total length of a v1 cookie (1 + 32 + 32).
  static const int byteLength = 1 + 32 + 32;

  /// Mint a cookie binding [transcriptHashCh1] to the (ip, port) of the
  /// client that sent CH1. [macKey] is the server's persistent secret —
  /// generate 32 random bytes once and keep them for the lifetime of
  /// the server.
  static Uint8List mint({
    required Uint8List macKey,
    required Uint8List transcriptHashCh1,
    required String clientIp,
    required int clientPort,
  }) {
    if (transcriptHashCh1.length != Sha256.digestLength) {
      throw ArgumentError('transcript hash must be ${Sha256.digestLength} bytes');
    }
    final input = _buildHmacInput(
      transcriptHashCh1: transcriptHashCh1,
      clientIp: clientIp,
      clientPort: clientPort,
    );
    final tag = HmacSha256.compute(macKey, input);
    final cookie = Uint8List(byteLength);
    cookie[0] = versionByte;
    cookie.setRange(1, 1 + 32, transcriptHashCh1);
    cookie.setRange(1 + 32, byteLength, tag);
    return cookie;
  }

  /// Parsed view of a cookie's transcript hash plus the bool of HMAC
  /// validity. Returns null on length / version error.
  static DtlsV13CookieParse? open({
    required Uint8List macKey,
    required Uint8List cookie,
    required String clientIp,
    required int clientPort,
  }) {
    if (cookie.length != byteLength) return null;
    if (cookie[0] != versionByte) return null;
    final transcriptHash = Uint8List.fromList(cookie.sublist(1, 1 + 32));
    final tag = Uint8List.fromList(cookie.sublist(1 + 32, byteLength));
    final input = _buildHmacInput(
      transcriptHashCh1: transcriptHash,
      clientIp: clientIp,
      clientPort: clientPort,
    );
    final expected = HmacSha256.compute(macKey, input);
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ tag[i];
    }
    return DtlsV13CookieParse(
      transcriptHashCh1: transcriptHash,
      isValid: diff == 0,
    );
  }

  static Uint8List _buildHmacInput({
    required Uint8List transcriptHashCh1,
    required String clientIp,
    required int clientPort,
  }) {
    if (clientPort < 0 || clientPort > 0xFFFF) {
      throw ArgumentError('client port out of range: $clientPort');
    }
    final endpointId = utf8.encode('$clientIp:$clientPort');
    final out = Uint8List(1 + transcriptHashCh1.length + endpointId.length);
    out[0] = versionByte;
    out.setRange(1, 1 + transcriptHashCh1.length, transcriptHashCh1);
    out.setRange(
      1 + transcriptHashCh1.length,
      out.length,
      endpointId,
    );
    return out;
  }
}

/// Result of [DtlsV13Cookie.open] — both the recovered transcript hash
/// and a bool of HMAC verification, so the caller can hand the
/// transcript bytes back into the handshake even when it's the act of
/// inspection alone (e.g., logging) and validity is checked separately.
final class DtlsV13CookieParse {
  /// SHA-256 of CH1 as it was when HRR was emitted.
  final Uint8List transcriptHashCh1;

  /// True only when the HMAC tag matches the server's `macKey` and the
  /// (ip, port) the cookie claims.
  final bool isValid;

  const DtlsV13CookieParse({
    required this.transcriptHashCh1,
    required this.isValid,
  });
}
