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
      expect(cands.first.ip, equals(IpAddress.parse('192.168.1.1')));
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

    test('buildDataChannelSdp omits host candidate when localIp is null',
        () {
      final built = SdpBuilder.buildDataChannelSdp(
        ufrag: 'u',
        password: 'pwd0123456789012345678',
        fingerprint: 'AA:' * 31 + 'BB',
        isOffer: true,
        sctpPort: 5000,
      );
      expect(built.media.single.candidates, isEmpty);
      final sdpText = built.build();
      expect(sdpText, isNot(contains('a=candidate:')));
    });
  });

  group('SdpParser.parseCandidate', () {
    test('parses a valid candidate line', () {
      const line = 'candidate:1 1 udp 2122260223 192.168.1.100 54400 typ host';
      final result = SdpParser.parseCandidate(line);
      expect(result.isOk, isTrue);
    });
  });

  group('SdpBuilder.buildAnswerFromOffer canonical codec names', () {
    // Regression: when a (non-conforming) offerer sends non-canonical
    // codec case — e.g. `vp8` / `OPUS` / `h264` — the answer must
    // emit the IANA-canonical form (`VP8` / `opus` / `H264`) instead
    // of echoing the offerer's bytes. Matches libwebrtc / Pion /
    // aiortc / Firefox behaviour and keeps `getStats().mimeType`
    // consistent with what browsers report.
    SdpSessionDescription parseOffer(String sdp) {
      final r = SdpParser.parse(sdp);
      expect(r.isOk, isTrue);
      return r.value;
    }

    String rtpmapLineFor(SdpSessionDescription answer, String pt) =>
        answer.media.single
            .getAll('rtpmap')
            .singleWhere((l) => l.startsWith('$pt '));

    test('lowercase `vp8` offer is answered with canonical `VP8`', () {
      final offerSdp = 'v=0\r\n'
          'o=- 1 2 IN IP4 0.0.0.0\r\n'
          's=-\r\n'
          't=0 0\r\n'
          'a=group:BUNDLE 0\r\n'
          'm=video 9 UDP/TLS/RTP/SAVPF 96\r\n'
          'c=IN IP4 0.0.0.0\r\n'
          'a=mid:0\r\n'
          'a=sendrecv\r\n'
          'a=rtpmap:96 vp8/90000\r\n'
          'a=ice-ufrag:abcd\r\n'
          'a=ice-pwd:abcdefghijklmnopqrstuv\r\n'
          'a=fingerprint:sha-256 ${'AA:' * 31}BB\r\n'
          'a=setup:actpass\r\n'
          'a=rtcp-mux\r\n';
      final answer = SdpBuilder.buildAnswerFromOffer(
        remoteOffer: parseOffer(offerSdp),
        ufrag: 'u',
        password: 'pwd0123456789012345678',
        fingerprint: 'AA:' * 31 + 'BB',
        supportedVideoCodecs: ['VP8'],
      );
      expect(rtpmapLineFor(answer, '96'), equals('96 VP8/90000'));
    });

    test('uppercase `OPUS` offer is answered with canonical `opus`', () {
      final offerSdp = 'v=0\r\n'
          'o=- 1 2 IN IP4 0.0.0.0\r\n'
          's=-\r\n'
          't=0 0\r\n'
          'a=group:BUNDLE 0\r\n'
          'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n'
          'c=IN IP4 0.0.0.0\r\n'
          'a=mid:0\r\n'
          'a=sendrecv\r\n'
          'a=rtpmap:111 OPUS/48000/2\r\n'
          'a=ice-ufrag:abcd\r\n'
          'a=ice-pwd:abcdefghijklmnopqrstuv\r\n'
          'a=fingerprint:sha-256 ${'AA:' * 31}BB\r\n'
          'a=setup:actpass\r\n'
          'a=rtcp-mux\r\n';
      final answer = SdpBuilder.buildAnswerFromOffer(
        remoteOffer: parseOffer(offerSdp),
        ufrag: 'u',
        password: 'pwd0123456789012345678',
        fingerprint: 'AA:' * 31 + 'BB',
        supportedAudioCodecs: ['opus'],
      );
      // Channels suffix preserved verbatim.
      expect(rtpmapLineFor(answer, '111'), equals('111 opus/48000/2'));
    });

    test('canonical-case offer passes through unchanged', () {
      // Sanity check that the rewrite doesn't perturb the common case
      // where the offerer already used IANA-canonical case (Chrome,
      // Firefox, libwebrtc, Pion, aiortc all do).
      final offerSdp = 'v=0\r\n'
          'o=- 1 2 IN IP4 0.0.0.0\r\n'
          's=-\r\n'
          't=0 0\r\n'
          'a=group:BUNDLE 0\r\n'
          'm=video 9 UDP/TLS/RTP/SAVPF 102\r\n'
          'c=IN IP4 0.0.0.0\r\n'
          'a=mid:0\r\n'
          'a=sendrecv\r\n'
          'a=rtpmap:102 H264/90000\r\n'
          'a=ice-ufrag:abcd\r\n'
          'a=ice-pwd:abcdefghijklmnopqrstuv\r\n'
          'a=fingerprint:sha-256 ${'AA:' * 31}BB\r\n'
          'a=setup:actpass\r\n'
          'a=rtcp-mux\r\n';
      final answer = SdpBuilder.buildAnswerFromOffer(
        remoteOffer: parseOffer(offerSdp),
        ufrag: 'u',
        password: 'pwd0123456789012345678',
        fingerprint: 'AA:' * 31 + 'BB',
        supportedVideoCodecs: ['H264'],
      );
      expect(rtpmapLineFor(answer, '102'), equals('102 H264/90000'));
    });
  });
}
