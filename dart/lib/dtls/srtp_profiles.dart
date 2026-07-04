/// RFC 5764 `use_srtp` profile negotiation, shared by the DTLS 1.2 and
/// DTLS 1.3 state machines: the supported-profile constants, server-side
/// `pick`, and the per-profile keying-material export length.
library;

/// SRTP protection-profile negotiation helpers (RFC 5764 §4.1.2, GCM
/// profiles from RFC 7714 §14.2).
abstract final class SrtpProfileNegotiation {
  SrtpProfileNegotiation._();

  // Profile IDs.
  static const int aes128CmHmacSha180 = 0x0001; // SRTP_AES128_CM_HMAC_SHA1_80
  static const int aes128CmHmacSha132 = 0x0002; // SRTP_AES128_CM_HMAC_SHA1_32
  static const int aeadAes128Gcm = 0x0007; // SRTP_AEAD_AES_128_GCM
  static const int aeadAes256Gcm = 0x0008; // SRTP_AEAD_AES_256_GCM

  /// DTLS 1.2 server preference: AES-CM first, AEAD_AES_128_GCM as the only
  /// fallback. Both Chrome and Firefox advertise 0x0001, so this picks the
  /// common-denominator profile and avoids known webdartc AES-GCM
  /// key-derivation issues (RFC 7714 §11 — 12-byte master salt, not 14).
  ///
  /// ⚠ Deliberately diverges from [v13Preference]; unifying the order
  /// changes negotiation results and is tracked in BACKLOG.md ("use_srtp
  /// offers only one SRTP profile") as a separate decision.
  static const List<int> v12Preference = <int>[
    aes128CmHmacSha180,
    aeadAes128Gcm,
  ];

  /// DTLS 1.3 server preference: AEAD-GCM first — it provides authenticated
  /// encryption in a single pass and is what current browsers prefer —
  /// with AES-CM-HMAC-SHA1 as an interop fallback (RFC 5764 §4.1.2 leaves
  /// profile choice to the server). See the [v12Preference] divergence note.
  static const List<int> v13Preference = <int>[
    aeadAes128Gcm,
    aeadAes256Gcm,
    aes128CmHmacSha180,
    aes128CmHmacSha132,
  ];

  /// The first profile in [preference] that the client [offered], or null
  /// when there is no overlap (use_srtp is then not negotiated).
  static int? pick(List<int> offered, {required List<int> preference}) {
    for (final id in preference) {
      if (offered.contains(id)) return id;
    }
    return null;
  }

  /// Bytes of TLS-exported keying material the negotiated profile expects
  /// (RFC 5764 §4.2 / RFC 7714 §12): 2×master key + 2×master salt.
  static int exportLength(int profileId) {
    switch (profileId) {
      case aes128CmHmacSha180:
      case aes128CmHmacSha132:
        return 60; // 16 + 16 + 14 + 14
      case aeadAes128Gcm:
        return 56; // 16 + 16 + 12 + 12
      case aeadAes256Gcm:
        return 88; // 32 + 32 + 12 + 12
      default:
        // Unknown profile — fall back to the legacy 60-byte default; a
        // mis-sized export will surface as a key-derivation mismatch
        // rather than a silent truncation.
        return 60;
    }
  }
}
