import '../peer_connection/peer_connection.dart';
import 'setting_engine.dart';

/// Factory that owns a shared [SettingEngine] and produces
/// [PeerConnection] instances configured with it.
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
final class Webdartc {
  final SettingEngine settingEngine;

  const Webdartc({this.settingEngine = const SettingEngine()});

  PeerConnection createPeerConnection({
    PeerConnectionConfiguration configuration =
        const PeerConnectionConfiguration(),
  }) =>
      PeerConnection(
        configuration: configuration,
        settingEngine: settingEngine,
      );
}
