import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('Webdartc factory', () {
    test('default factory produces a PeerConnection with a default engine', () {
      const rtc = Webdartc();
      final pc = rtc.createPeerConnection();
      expect(pc.settingEngine.bindAddresses, isNull);
      expect(pc.settingEngine.udpPortRange, isNull);
      expect(pc.settingEngine.includeLoopbackCandidate, isFalse);
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

    test('direct constructor accepts settingEngine', () {
      const setting = SettingEngine(bindAddresses: ['10.0.0.1']);
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        settingEngine: setting,
      );
      expect(identical(pc.settingEngine, setting), isTrue);
    });

    test('direct constructor without settingEngine uses the default', () {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      expect(pc.settingEngine.bindAddresses, isNull);
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
