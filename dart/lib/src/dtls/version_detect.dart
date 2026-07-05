/// Server-side DTLS version detection — the single place that sniffs a
/// first ClientHello to decide between the DTLS 1.2 and DTLS 1.3 paths.
library;

import 'dart:typed_data';

import 'record.dart';
import 'v13/handshake.dart' as v13;

enum DtlsVersion { v12, v13 }

/// Inspects a server-bound first datagram and decides which DTLS version
/// the client is offering.
///
/// Returns:
/// - [DtlsVersion.v13] — a ClientHello whose `supported_versions` extension
///   lists `0xFEFC`, or a *fragmented* ClientHello. The fragmented heuristic
///   is needed for WebRTC clients (Firefox, Chrome) whose DTLS 1.3
///   ClientHellos exceed the path MTU and split across multiple datagrams:
///   v1.2 ClientHellos are small enough to fit a single record, so a
///   fragment is almost certainly DTLS 1.3 and must be routed to the v1.3
///   state machine so it can reassemble before parsing.
/// - [DtlsVersion.v12] — a parseable, unfragmented ClientHello without a
///   DTLS 1.3 offer.
/// - `null` — not a parseable ClientHello.
DtlsVersion? detectDtlsVersion(Uint8List packet) {
  final rec = DtlsRecord.parse(packet, 0);
  if (rec == null) return null;
  if (rec.epoch != 0) return null;
  if (rec.contentType != DtlsContentType.handshake) return null;
  final hs = DtlsHandshakeHeader.parse(rec.fragment);
  if (hs == null) return null;
  if (hs.msgType != v13.TlsV13HandshakeType.clientHello) return null;
  if (hs.fragmentOffset != 0 || hs.fragmentLength != hs.length) {
    // Fragmented ClientHello: assume DTLS 1.3 (see doc comment).
    return DtlsVersion.v13;
  }
  final ch = v13.parseClientHello(hs.body);
  if (ch == null) return null;
  final sv = ch.extensionByType(v13.TlsV13ExtensionType.supportedVersions);
  if (sv == null) {
    // No supported_versions ⇒ pre-TLS 1.3 client.
    return DtlsVersion.v12;
  }
  final versions = v13.parseClientHelloSupportedVersionsExtData(sv.data);
  if (versions == null) return DtlsVersion.v12;
  return versions.contains(v13.dtls13Version)
      ? DtlsVersion.v13
      : DtlsVersion.v12;
}
