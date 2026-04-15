import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('SdpParser', () {
    const sampleOffer = '''v=0
o=- 1234567890 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=mid:0
a=ice-ufrag:abc1
a=ice-pwd:password123
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99
a=setup:actpass
a=sctp-port:5000
a=candidate:1 1 udp 2122260223 192.168.1.1 9999 typ host
''';

    test('parse session-level attributes', () {
      final result = SdpParser.parse(sampleOffer);
      expect(result.isOk, isTrue);
      final sdp = result.value;
      expect(sdp.sessionAttributes['group'], equals('BUNDLE 0'));
    });

    test('parse media section', () {
      final result = SdpParser.parse(sampleOffer);
      expect(result.isOk, isTrue);
      final sdp = result.value;
      expect(sdp.media.length, equals(1));
      final m = sdp.media.first;
      expect(m.type, equals('application'));
      expect(m.proto, equals('UDP/DTLS/SCTP'));
      expect(m.iceUfrag, equals('abc1'));
      expect(m.icePwd, equals('password123'));
      expect(m.setup, equals('actpass'));
    });

    test('parse ICE candidates', () {
      final result = SdpParser.parse(sampleOffer);
      expect(result.isOk, isTrue);
      final cands = result.value.media.first.candidates;
      expect(cands.length, equals(1));
      expect(cands.first.ip, equals('192.168.1.1'));
      expect(cands.first.port, equals(9999));
      expect(cands.first.type, equals(IceCandidateType.host));
    });

    test('build/parse round-trip for data channel SDP', () {
      final built = SdpBuilder.buildDataChannelSdp(
        ufrag: 'ufrag1',
        password: 'password1234567890123',
        fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'
            ':AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
        isOffer: true,
        sctpPort: 5000,
        localIp: '127.0.0.1',
        localPort: 12345,
      );
      final sdpText = built.build();
      final parsed = SdpParser.parse(sdpText);
      expect(parsed.isOk, isTrue);
      final media = parsed.value.media.first;
      expect(media.iceUfrag, equals('ufrag1'));
      expect(media.setup, equals('actpass'));
    });
  });

  group('SdpParser.parseCandidate', () {
    test('parses a valid candidate line', () {
      const line = 'candidate:1 1 udp 2122260223 192.168.1.100 54400 typ host';
      final result = SdpParser.parseCandidate(line);
      expect(result.isOk, isTrue);
    });
  });
}
