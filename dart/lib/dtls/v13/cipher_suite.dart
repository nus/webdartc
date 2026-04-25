/// TLS 1.3 cipher suite metadata (RFC 8446 Appendix B.4).
///
/// This module records the fixed parameters each cipher suite imposes on
/// the rest of the stack: AEAD key/iv/tag lengths and the hash length used
/// throughout the key schedule and Finished verify_data.
///
/// Phase 1 only registers the mandatory-to-implement suite
/// `TLS_AES_128_GCM_SHA256` — the same suite Firefox 150 picks for
/// WebRTC by default. Additional suites can be added without changing
/// callers as long as they share the AEAD nonce / tag layout.
final class TlsV13CipherSuite {
  /// Wire identifier as carried in ClientHello / ServerHello.
  final int id;

  /// IANA name (purely informational; useful in logs and tests).
  final String name;

  /// Length of the AEAD encryption key in bytes (RFC 8446 §5.2). Also
  /// used as the length of the DTLS sequence-number protection key
  /// (`sn_key`) when the suite is AES-based (RFC 9147 §4.2.3).
  final int keyLength;

  /// Length of the AEAD nonce in bytes. 12 for every TLS 1.3 suite
  /// currently registered.
  final int ivLength;

  /// Length of the suite's hash output. Used as `Hash.length` in the key
  /// schedule (RFC 8446 §7.1) and as the length of `Finished.verify_data`.
  final int hashLength;

  /// AEAD authentication tag length. 16 for every TLS 1.3 suite.
  final int tagLength;

  const TlsV13CipherSuite({
    required this.id,
    required this.name,
    required this.keyLength,
    required this.ivLength,
    required this.hashLength,
    required this.tagLength,
  });

  /// `TLS_AES_128_GCM_SHA256` (0x1301) — the mandatory-to-implement
  /// suite and the only one Phase 1 supports.
  static const TlsV13CipherSuite aes128GcmSha256 = TlsV13CipherSuite(
    id: 0x1301,
    name: 'TLS_AES_128_GCM_SHA256',
    keyLength: 16,
    ivLength: 12,
    hashLength: 32,
    tagLength: 16,
  );

  /// All registered cipher suites in implementation-preference order.
  static const List<TlsV13CipherSuite> supported = [aes128GcmSha256];

  /// Look up a registered suite by wire ID, or null.
  static TlsV13CipherSuite? byId(int id) {
    for (final s in supported) {
      if (s.id == id) return s;
    }
    return null;
  }

  /// Pick the first ID in [clientOffered] that this implementation
  /// supports. Returns null when nothing overlaps — the caller should
  /// then send an `insufficient_security` alert and abort.
  ///
  /// Selection order follows the *server's* preference: we walk the
  /// client's list and accept the first match against our [supported]
  /// list, matching the common server-preference behaviour.
  static TlsV13CipherSuite? selectFromOffer(List<int> clientOffered) {
    for (final id in clientOffered) {
      final s = byId(id);
      if (s != null) return s;
    }
    return null;
  }
}
