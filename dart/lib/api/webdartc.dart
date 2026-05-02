import '../peer_connection/peer_connection.dart';
import 'media_engine.dart';
import 'setting_engine.dart';

/// Pion-style factory that owns shared configuration ([SettingEngine],
/// [MediaEngine]) and produces [PeerConnection] instances. The W3C
/// API surface (`PeerConnection`, `PeerConnectionConfiguration`,
/// `IceServer`, …) is unchanged; this factory is the entry point for
/// implementation-level configuration that does not have a W3C
/// equivalent.
///
/// Typical usage:
///
/// ```dart
/// const rtc = Webdartc(
///   settingEngine: SettingEngine(
///     bindAddresses: ['127.0.0.1'],
///     udpPortRange: (40000, 50000),
///   ),
/// );
/// final pc = rtc.createPeerConnection(
///   configuration: const PeerConnectionConfiguration(),
/// );
/// ```
///
/// The legacy `PeerConnection(configuration: ...)` constructor is
/// preserved and behaves as if it had been created by a default
/// `Webdartc()` — every PC always has a `SettingEngine` /
/// `MediaEngine`; the factory only lets you swap the defaults.
final class Webdartc {
  final SettingEngine settingEngine;
  final MediaEngine mediaEngine;

  const Webdartc({
    this.settingEngine = const SettingEngine(),
    this.mediaEngine = const MediaEngine(),
  });

  PeerConnection createPeerConnection({
    PeerConnectionConfiguration configuration =
        const PeerConnectionConfiguration(),
  }) {
    final pc = PeerConnection(configuration: configuration);
    pc.attachEngines(setting: settingEngine, media: mediaEngine);
    return pc;
  }
}
