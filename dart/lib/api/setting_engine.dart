import 'dart:io';

/// Low-level network / ICE configuration shared across all
/// [PeerConnection]s created by a [WebdartcApi].
///
/// Mirrors Pion's `webrtc.SettingEngine` — fields here cover knobs that
/// the W3C [PeerConnectionConfiguration] does not expose because they
/// are implementation-level (specific bind addresses, ephemeral port
/// ranges, interface filters). Construct with named arguments and
/// `const` whenever possible:
///
/// ```dart
/// const setting = SettingEngine(
///   bindAddresses: ['127.0.0.1'],
///   udpPortRange: (40000, 50000),
///   includeLoopbackCandidate: true,
/// );
/// ```
final class SettingEngine {
  /// Specific local IPv4 / IPv6 addresses to bind UDP sockets to. One
  /// host candidate is gathered per address. When `null`, the transport
  /// auto-enumerates non-loopback interfaces (filtered by
  /// [interfaceFilter] if set, plus loopback when
  /// [includeLoopbackCandidate] is true).
  final List<String>? bindAddresses;

  /// Inclusive ephemeral UDP port range `(min, max)` the transport may
  /// pick from when binding sockets. `null` lets the OS choose any
  /// ephemeral port (Dart `bind(addr, 0)` semantics). Mirrors Pion's
  /// `SetEphemeralUDPPortRange(min, max)`.
  final (int, int)? udpPortRange;

  /// Predicate used to filter the interfaces enumerated when
  /// [bindAddresses] is `null`. Returning `false` excludes the
  /// interface from candidate gathering. Mirrors Pion's
  /// `SetInterfaceFilter`. Cannot participate in `const` construction
  /// (closures are not const-compatible); the [SettingEngine] holding
  /// a non-null filter is therefore non-const.
  final bool Function(NetworkInterface)? interfaceFilter;

  /// When `true` and [bindAddresses] is `null`, loopback addresses
  /// (`127.0.0.1`, `::1`) are included as host candidates in addition
  /// to non-loopback interface IPs. Useful for loopback-only e2e
  /// testing. Mirrors Pion's `SetIncludeLoopbackCandidate`.
  final bool includeLoopbackCandidate;

  const SettingEngine({
    this.bindAddresses,
    this.udpPortRange,
    this.interfaceFilter,
    this.includeLoopbackCandidate = false,
  });
}
