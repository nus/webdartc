import 'dart:typed_data';

import '../../crypto/sha256.dart';

/// DTLS 1.3 handshake transcript (RFC 9147 §5.2 + RFC 8446 §4.4.1).
///
/// Each handshake message contributes only its TLS-1.3-style form to the
/// transcript: `type(1) + length(3) + body`. The DTLS-specific fields
/// `message_seq` (2 bytes), `fragment_offset` (3 bytes), and
/// `fragment_length` (3 bytes) are excluded entirely so that retransmission
/// and fragmentation never affect the hash.
///
/// Receivers must reassemble fragmented messages before adding them — each
/// fragment carries only part of the body and would otherwise yield a
/// different hash.
final class DtlsV13Transcript {
  final List<Uint8List> _segments = [];

  /// Append a full DTLS handshake message after stripping its DTLS-specific
  /// header bytes.
  ///
  /// The DTLS handshake header layout (RFC 9147 §5.2) is:
  ///
  ///   type(1) + length(3) + msg_seq(2) + frag_offset(3) + frag_length(3)
  ///
  /// We keep only `type` and `length`; the eight bytes at offsets `4..11`
  /// are dropped. The DTLS `length` field already carries the full message
  /// length, so the surviving header matches the TLS 1.3 layout exactly.
  void addDtlsMessage(Uint8List dtlsMessage) {
    if (dtlsMessage.length < 12) {
      throw ArgumentError(
        'DTLS handshake header requires at least 12 bytes',
      );
    }
    final body = dtlsMessage.length - 12;
    final tls = Uint8List(4 + body);
    tls[0] = dtlsMessage[0];
    tls[1] = dtlsMessage[1];
    tls[2] = dtlsMessage[2];
    tls[3] = dtlsMessage[3];
    tls.setRange(4, tls.length, dtlsMessage, 12);
    _segments.add(tls);
  }

  /// Append an already-TLS-1.3-form handshake message verbatim.
  ///
  /// Use this for messages constructed in TLS form (no DTLS header to strip)
  /// or for the synthetic `message_hash` produced by [replaceWithSyntheticHash].
  void addRawTlsMessage(Uint8List tlsMessage) {
    _segments.add(Uint8List.fromList(tlsMessage));
  }

  /// SHA-256 hash of the concatenated transcript bytes.
  Uint8List get hash {
    final total = _segments.fold<int>(0, (n, s) => n + s.length);
    final all = Uint8List(total);
    var off = 0;
    for (final s in _segments) {
      all.setRange(off, off + s.length, s);
      off += s.length;
    }
    return Sha256.hash(all);
  }

  /// Replace the current transcript with a single synthetic `message_hash`
  /// (RFC 8446 §4.4.1):
  ///
  ///   message_hash := type=0xFE || uint24(Hash.length) || Hash(prev_transcript)
  ///
  /// Called by the client after receiving a HelloRetryRequest so that
  /// `ClientHello1` is retained only as its hash before `HelloRetryRequest`
  /// and `ClientHello2` are appended.
  void replaceWithSyntheticHash() {
    final h = hash;
    final synthetic = Uint8List(4 + h.length);
    synthetic[0] = 0xFE;
    synthetic[1] = (h.length >> 16) & 0xFF;
    synthetic[2] = (h.length >> 8) & 0xFF;
    synthetic[3] = h.length & 0xFF;
    synthetic.setRange(4, synthetic.length, h);
    _segments
      ..clear()
      ..add(synthetic);
  }

  /// Discard all accumulated messages.
  void clear() => _segments.clear();

  /// Number of accumulated messages (primarily for tests / diagnostics).
  int get length => _segments.length;
}
