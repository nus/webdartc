import '../peer_connection/peer_connection.dart';
import 'media_engine.dart';
import 'setting_engine.dart';

/// Factory that owns a shared [SettingEngine] and [MediaEngine] and
/// produces [PeerConnection] instances configured with them.
///
/// ```dart
/// const rtc = Webdartc(
///   settingEngine: SettingEngine(
///     bindAddresses: ['127.0.0.1'],
///     udpPortRange: (40000, 50000),
///   ),
///   mediaEngine: MediaEngine(),  // VP8 + H.264 + Opus by default
/// );
/// final pc = rtc.createPeerConnection(
///   configuration: const PeerConnectionConfiguration(),
/// );
/// ```
final class Webdartc {
  final SettingEngine settingEngine;
  final MediaEngine mediaEngine;

  /// Whether each created [PeerConnection] auto-registers the bundled codec
  /// backends (VP8, VP9, H.264, Opus) so the W3C receive path decodes out of
  /// the box. Set false to control which backends are available yourself.
  /// Registration is lazy at the native-library level — see [PeerConnection].
  final bool autoRegisterCodecs;

  const Webdartc({
    this.settingEngine = const SettingEngine(),
    this.mediaEngine = const MediaEngine(),
    this.autoRegisterCodecs = true,
  });

  PeerConnection createPeerConnection({
    PeerConnectionConfiguration configuration =
        const PeerConnectionConfiguration(),
  }) =>
      PeerConnection(
        configuration: configuration,
        settingEngine: settingEngine,
        mediaEngine: mediaEngine,
        autoRegisterCodecs: autoRegisterCodecs,
      );
}
