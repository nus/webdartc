/// Shared `SettingEngine` for all e2e helpers.
library;

import 'dart:io';

import 'package:webdartc/api/setting_engine.dart';

/// Engine all e2e helpers register their PeerConnection against.
///
/// - `includeLoopbackCandidate: true` so ICE has a `127.0.0.1 ↔
///   127.0.0.1` pair to try alongside the non-loopback ones. Important
///   on Windows where sending UDP from a non-loopback NIC back to the
///   same NIC fails with errno 1214 (ERROR_BAD_NET_NAME). The
///   non-loopback candidates stay in the set for Firefox tests, which
///   don't pair to loopback by default.
/// - `interfaceFilter`: drops Windows Hyper-V virtual switches from
///   candidate gathering. The hosted `windows-latest` runner exposes
///   those interfaces but UDP `bind` against them fails sporadically
///   with `errno=1214` / `errno=1231`; the resulting socket errors slip
///   past the 15-20 s per-scenario `waitFor` budget and the whole E2E
///   job retries pointlessly. Excluding them keeps ICE pairing bounded
///   to the loopback + the real physical NIC.
final e2eSettings = SettingEngine(
  includeLoopbackCandidate: true,
  interfaceFilter: _isE2eAddressableInterface,
);

bool _isE2eAddressableInterface(NetworkInterface iface) {
  // `vEthernet (...)` is the Windows Hyper-V virtual-switch naming
  // convention — covers `vEthernet (Default Switch)`,
  // `vEthernet (WSL)`, `vEthernet (WSL (Hyper-V firewall))`, etc.
  if (Platform.isWindows && iface.name.startsWith('vEthernet (')) {
    return false;
  }
  return true;
}
