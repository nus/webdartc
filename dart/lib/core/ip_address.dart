import 'dart:io' show InternetAddress;
import 'dart:typed_data';

/// Immutable IP address value type — IPv4 (4 bytes) or IPv6 (16 bytes) in
/// canonical form. Used everywhere internally so that two textually
/// different but semantically identical addresses (`0:0:0:0:0:0:0:1` vs
/// `::1`, `192.168.1.5` vs `::ffff:192.168.1.5`) hash and compare
/// consistently.
///
/// Conversion is performed once at I/O boundaries (`Datagram`, SDP, STUN,
/// `SettingEngine`); downstream code uses [IpAddress] directly.
final class IpAddress {
  final Uint8List _bytes;
  String? _canonical;

  IpAddress._(this._bytes);

  /// Parse a textual IP literal. Accepts dotted-quad IPv4 and any IPv6
  /// form recognised by `dart:io`'s [InternetAddress] (including
  /// IPv4-mapped IPv6 such as `::ffff:1.2.3.4`, which is preserved as a
  /// 16-byte IPv6 value).
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
    final addr = InternetAddress.tryParse(s);
    if (addr == null) return null;
    return IpAddress._(Uint8List.fromList(addr.rawAddress));
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

  /// True if this address is on the loopback range (`127.0.0.0/8` for
  /// IPv4, `::1` for IPv6). Delegates to `dart:io`.
  bool get isLoopback => InternetAddress.fromRawAddress(_bytes).isLoopback;

  /// True if all bytes are zero (`0.0.0.0` / `::`). The "any" address
  /// used for wildcard binds.
  bool get isUnspecified {
    for (final b in _bytes) {
      if (b != 0) return false;
    }
    return true;
  }

  /// True if this is in the auto-configured link-local range
  /// (`169.254.0.0/16` for IPv4, `fe80::/10` for IPv6). RFC 4291 §2.5.6
  /// — `dart:io`'s `isLinkLocal` is stricter than `/10`, so handle it
  /// here.
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
  /// shortest run of zero groups compressed). Cached on first call —
  /// hot paths (DTLS / SCTP / ICE OutputPacket builders) call this on
  /// every emitted record.
  String toCanonical() =>
      _canonical ??= InternetAddress.fromRawAddress(_bytes).address;

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
}
