import 'dart:typed_data';

/// Immutable IP address value type — IPv4 (4 bytes) or IPv6 (16 bytes) in
/// canonical form. Used everywhere internally so that two textually
/// different but semantically identical addresses (`0:0:0:0:0:0:0:1` vs
/// `::1`, `192.168.1.5` vs `::ffff:192.168.1.5`) hash and compare
/// consistently.
///
/// Conversion is performed once at I/O boundaries (`Datagram`, SDP, STUN,
/// `SettingEngine`); downstream code uses [IpAddress] directly.
///
/// Pure Dart — parsing, canonical formatting (classic BSD `inet_ntop`
/// rules, matching what `dart:io`'s `InternetAddress.address` produced when
/// this type delegated to it), and the classification getters have no
/// `dart:io` dependency.
final class IpAddress {
  final Uint8List _bytes;
  String? _canonical;

  IpAddress._(this._bytes);

  /// Parse a textual IP literal. Accepts dotted-quad IPv4 (leading zeros
  /// tolerated, e.g. `01.2.3.4`) and any RFC 4291 IPv6 form including
  /// `::` compression, embedded IPv4 tails, and a `%zone` suffix (the zone
  /// is dropped). IPv4-mapped IPv6 such as `::ffff:1.2.3.4` is preserved
  /// as a 16-byte IPv6 value.
  ///
  /// Throws [FormatException] on invalid input. Hostnames are rejected.
  factory IpAddress.parse(String s) {
    final parsed = tryParse(s);
    if (parsed == null) {
      throw FormatException('Invalid IP address literal', s);
    }
    return parsed;
  }

  /// Like [parse], but returns null on invalid input instead of throwing.
  static IpAddress? tryParse(String s) {
    if (s.contains(':')) {
      // IPv6, optionally with a "%zone" suffix (dropped, as
      // InternetAddress.tryParse did).
      var host = s;
      final pct = s.indexOf('%');
      if (pct != -1) host = s.substring(0, pct);
      final bytes = _parseV6(host);
      return bytes == null ? null : IpAddress._(bytes);
    }
    final bytes = _parseV4(s);
    return bytes == null ? null : IpAddress._(bytes);
  }

  /// Construct from the canonical byte form (4 bytes for IPv4, 16 bytes
  /// for IPv6). The input is copied; mutation of [bytes] after the call
  /// does not affect the constructed address.
  factory IpAddress.fromBytes(Uint8List bytes) {
    if (bytes.length != 4 && bytes.length != 16) {
      throw ArgumentError(
        'IpAddress requires 4 (IPv4) or 16 (IPv6) bytes; got ${bytes.length}',
      );
    }
    return IpAddress._(Uint8List.fromList(bytes));
  }

  /// True if this is an IPv4 address (4-byte form).
  bool get isV4 => _bytes.length == 4;

  /// True if this is an IPv6 address (16-byte form). IPv4-mapped IPv6
  /// addresses are IPv6 (use [isIpv4MappedIpv6] to detect them).
  bool get isV6 => _bytes.length == 16;

  /// True if this address is on the loopback range: `127.0.0.0/8` for
  /// IPv4, exactly `::1` for IPv6 (an IPv4-mapped `::ffff:127.0.0.1` is
  /// not loopback, matching `dart:io`'s InternetAddress).
  bool get isLoopback {
    if (isV4) return _bytes[0] == 127;
    for (var i = 0; i < 15; i++) {
      if (_bytes[i] != 0) return false;
    }
    return _bytes[15] == 1;
  }

  /// True if all bytes are zero (`0.0.0.0` / `::`). The "any" address
  /// used for wildcard binds.
  bool get isUnspecified {
    for (final b in _bytes) {
      if (b != 0) return false;
    }
    return true;
  }

  /// True if this is in the auto-configured link-local range
  /// (`169.254.0.0/16` for IPv4, `fe80::/10` for IPv6). RFC 4291 §2.5.6.
  bool get isLinkLocal {
    if (isV4) return _bytes[0] == 169 && _bytes[1] == 254;
    return _bytes[0] == 0xfe && (_bytes[1] & 0xc0) == 0x80;
  }

  /// True if this is an IPv4-mapped IPv6 address (`::ffff:0:0/96`).
  bool get isIpv4MappedIpv6 {
    if (!isV6) return false;
    for (var i = 0; i < 10; i++) {
      if (_bytes[i] != 0) return false;
    }
    return _bytes[10] == 0xff && _bytes[11] == 0xff;
  }

  /// The canonical byte form (4 or 16 bytes). The returned view is
  /// unmodifiable; callers that need to mutate must copy explicitly.
  Uint8List toBytes() => _bytes.asUnmodifiableView();

  /// The canonical text form. IPv6 addresses follow RFC 5952 (lowercase,
  /// longest run of ≥2 zero groups compressed, leftmost on ties) with the
  /// classic BSD `inet_ntop` dotted-tail special cases (`::a.b.c.d` for a
  /// zero run covering exactly the first six groups, `::ffff:a.b.c.d` for
  /// IPv4-mapped). Cached on first call — hot paths (DTLS / SCTP / ICE
  /// OutputPacket builders) call this on every emitted record.
  String toCanonical() => _canonical ??= isV4 ? _dotted(0) : _formatV6();

  @override
  String toString() => toCanonical();

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! IpAddress) return false;
    if (_bytes.length != other._bytes.length) return false;
    for (var i = 0; i < _bytes.length; i++) {
      if (_bytes[i] != other._bytes[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode {
    var h = _bytes.length;
    for (final b in _bytes) {
      h = 0x1fffffff & (h * 33 + b);
    }
    return h;
  }

  // ── Parsing ───────────────────────────────────────────────────────────────

  /// Dotted-quad IPv4: four all-digit decimal octets ≤ 255. Leading zeros
  /// are tolerated (InternetAddress.tryParse compatibility).
  static Uint8List? _parseV4(String s) {
    final parts = s.split('.');
    if (parts.length != 4) return null;
    final out = Uint8List(4);
    for (var i = 0; i < 4; i++) {
      final part = parts[i];
      if (part.isEmpty) return null;
      var value = 0;
      for (var j = 0; j < part.length; j++) {
        final c = part.codeUnitAt(j);
        if (c < 0x30 || c > 0x39) return null;
        value = value * 10 + (c - 0x30);
        if (value > 255) return null;
      }
      out[i] = value;
    }
    return out;
  }

  static Uint8List? _parseV6(String host) {
    try {
      return Uint8List.fromList(Uri.parseIPv6Address(host));
    } on FormatException {
      // Uri.parseIPv6Address rejects leading zeros in an embedded IPv4
      // tail (`::ffff:01.2.3.4`), which InternetAddress accepted.
      // Normalize the tail and retry once.
      final lastColon = host.lastIndexOf(':');
      if (lastColon == -1 || !host.contains('.')) return null;
      final tail = _parseV4(host.substring(lastColon + 1));
      if (tail == null) return null;
      final normalized = '${host.substring(0, lastColon + 1)}'
          '${tail[0]}.${tail[1]}.${tail[2]}.${tail[3]}';
      try {
        return Uint8List.fromList(Uri.parseIPv6Address(normalized));
      } on FormatException {
        return null;
      }
    }
  }

  // ── Formatting ────────────────────────────────────────────────────────────

  /// Dotted-quad rendering of four bytes starting at [offset] (0 for an
  /// IPv4 address, 12 for an embedded IPv4 tail).
  String _dotted(int offset) => '${_bytes[offset]}.${_bytes[offset + 1]}.'
      '${_bytes[offset + 2]}.${_bytes[offset + 3]}';

  String _formatV6() {
    final words = List<int>.generate(
      8,
      (i) => (_bytes[2 * i] << 8) | _bytes[2 * i + 1],
    );

    // Longest run of ≥2 zero groups; leftmost wins ties.
    var bestBase = -1, bestLen = 0;
    var curBase = -1, curLen = 0;
    for (var i = 0; i < 8; i++) {
      if (words[i] == 0) {
        if (curBase == -1) {
          curBase = i;
          curLen = 1;
        } else {
          curLen++;
        }
        if (curLen > bestLen) {
          bestBase = curBase;
          bestLen = curLen;
        }
      } else {
        curBase = -1;
        curLen = 0;
      }
    }
    if (bestLen < 2) bestBase = -1;

    // Dotted IPv4 tail for the inet_ntop special cases: a zero run covering
    // exactly the first six groups, or five groups followed by ffff
    // (IPv4-mapped). A 7-group run is formatted as hex ("::1", "::100").
    final dottedTail = bestBase == 0 &&
        (bestLen == 6 || (bestLen == 5 && words[5] == 0xffff));

    final out = StringBuffer();
    var i = 0;
    while (i < 8) {
      if (i == bestBase) {
        out.write('::');
        i += bestLen;
        continue;
      }
      if (i != 0 && i != bestBase + bestLen) out.write(':');
      if (i == 6 && dottedTail) {
        out.write(_dotted(12));
        break;
      }
      out.write(words[i].toRadixString(16));
      i++;
    }
    return out.toString();
  }
}
