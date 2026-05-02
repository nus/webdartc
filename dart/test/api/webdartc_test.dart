import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('Webdartc factory', () {
    test('default factory produces a PeerConnection with default engines', () {
      const rtc = Webdartc();
      final pc = rtc.createPeerConnection();
      expect(pc.settingEngine.bindAddresses, isNull);
      expect(pc.settingEngine.udpPortRange, isNull);
      expect(pc.settingEngine.includeLoopbackCandidate, isFalse);
      expect(pc.mediaEngine, isA<MediaEngine>());
    });

    test('factory injects custom SettingEngine into the PC', () {
      const rtc = Webdartc(
        settingEngine: SettingEngine(
          bindAddresses: ['127.0.0.1'],
          udpPortRange: (40000, 50000),
          includeLoopbackCandidate: true,
        ),
      );
      final pc = rtc.createPeerConnection();
      expect(pc.settingEngine.bindAddresses, equals(['127.0.0.1']));
      expect(pc.settingEngine.udpPortRange, equals((40000, 50000)));
      expect(pc.settingEngine.includeLoopbackCandidate, isTrue);
    });

    test('factory forwards configuration to the PC', () {
      const rtc = Webdartc();
      final pc = rtc.createPeerConnection(
        configuration: const PeerConnectionConfiguration(
          bundlePolicy: 'balanced',
        ),
      );
      expect(pc.configuration.bundlePolicy, equals('balanced'));
    });

    test('legacy direct constructor still works with default engines', () {
      // This is the backward-compatible path — code that hasn't migrated
      // to Webdartc keeps working unchanged.
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      expect(pc.settingEngine.bindAddresses, isNull);
      expect(pc.mediaEngine, isA<MediaEngine>());
    });

    test('attachEngines on a fresh PC swaps the defaults', () {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      const setting = SettingEngine(bindAddresses: ['10.0.0.1']);
      const media = MediaEngine();
      pc.attachEngines(setting: setting, media: media);
      expect(pc.settingEngine.bindAddresses, equals(['10.0.0.1']));
      expect(identical(pc.settingEngine, setting), isTrue);
      expect(identical(pc.mediaEngine, media), isTrue);
    });

    test('SettingEngine is fully const-constructible', () {
      const a = SettingEngine();
      const b = SettingEngine(
        bindAddresses: ['127.0.0.1', '::1'],
        udpPortRange: (40000, 50000),
        includeLoopbackCandidate: true,
      );
      expect(identical(a, const SettingEngine()), isTrue);
      expect(identical(b, b), isTrue);
    });

    test('Webdartc is const-constructible with defaults', () {
      const x = Webdartc();
      const y = Webdartc();
      expect(identical(x, y), isTrue);
    });
  });
}
