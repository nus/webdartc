// Byte-exact snapshots of the SDP builder output, captured before the
// 2026-07 builder refactor (B-3). The builder output is browser-facing
// wire format — any diff here is an interop-relevant behavior change, not
// a formatting nit. The `o=` timestamp is normalized to `TS`.
import 'package:test/test.dart';
import 'package:webdartc/src/sdp/parser.dart';

const _dataChannelOffer = '''
v=0
o=- TS 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed:
a=msid-semantic: WMS
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=mid:0
a=ice-ufrag:UFRG
a=ice-pwd:pwd0123456789012345678901
a=ice-options:trickle
a=fingerprint:sha-256 AA:BB:CC
a=setup:actpass
a=sctp-port:5000
a=max-message-size:262144
a=candidate:1 1 udp 2130706431 192.168.1.10 40000 typ host
''';

const _dataChannelAnswer = '''
v=0
o=- TS 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed:
a=msid-semantic: WMS
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=mid:0
a=ice-ufrag:UFRG
a=ice-pwd:pwd0123456789012345678901
a=ice-options:trickle
a=fingerprint:sha-256 AA:BB:CC
a=setup:active
a=sctp-port:5000
a=max-message-size:262144
''';

const _mediaOffer = '''
v=0
o=- TS 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=extmap-allow-mixed:
a=msid-semantic: WMS
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=mid:0
a=ice-ufrag:UFRG
a=ice-pwd:pwd0123456789012345678901
a=ice-options:trickle
a=fingerprint:sha-256 AA:BB:CC
a=setup:actpass
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10;useinbandfec=1
a=rtcp-fb:111 transport-cc
a=ssrc:1111 cname:webdartc
a=ssrc:1111 msid:webdartc-stream webdartc-track-0
a=candidate:1 1 udp 2130706431 192.168.1.10 40000 typ host
m=video 9 UDP/TLS/RTP/SAVPF 96
c=IN IP4 0.0.0.0
a=mid:1
a=ice-ufrag:UFRG
a=ice-pwd:pwd0123456789012345678901
a=ice-options:trickle
a=fingerprint:sha-256 AA:BB:CC
a=setup:actpass
a=recvonly
a=rtcp-mux
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtcp-fb:96 goog-remb
a=candidate:1 1 udp 2130706431 192.168.1.10 40000 typ host
''';

const _answerFromOffer = '''
v=0
o=- TS 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1 2
a=extmap-allow-mixed:
a=msid-semantic: WMS
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=mid:0
a=ice-ufrag:UFRG
a=ice-pwd:pwd0123456789012345678901
a=ice-options:trickle
a=fingerprint:sha-256 AA:BB:CC
a=setup:active
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10
a=rtcp-fb:111 transport-cc
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=ssrc:2222 cname:webdartc
a=ssrc:2222 msid:webdartc-stream webdartc-track-0
a=candidate:1 1 udp 2130706431 192.168.1.10 40000 typ host
m=video 9 UDP/TLS/RTP/SAVPF 96
c=IN IP4 0.0.0.0
a=mid:1
a=ice-ufrag:UFRG
a=ice-pwd:pwd0123456789012345678901
a=ice-options:trickle
a=fingerprint:sha-256 AA:BB:CC
a=setup:active
a=recvonly
a=rtcp-mux
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 nack
a=candidate:1 1 udp 2130706431 192.168.1.10 40000 typ host
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=mid:2
a=ice-ufrag:UFRG
a=ice-pwd:pwd0123456789012345678901
a=ice-options:trickle
a=fingerprint:sha-256 AA:BB:CC
a=setup:active
a=sctp-port:5000
a=max-message-size:262144
a=candidate:1 1 udp 2130706431 192.168.1.10 40000 typ host
''';

const _rejectedMLineAnswer = '''
v=0
o=- TS 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed:
a=msid-semantic: WMS
m=video 0 UDP/TLS/RTP/SAVPF 97
c=IN IP4 0.0.0.0
''';

String _normalize(String sdp) =>
    sdp.replaceAll(RegExp(r'o=- \d+ 2 IN IP4'), 'o=- TS 2 IN IP4');

const _ufrag = 'UFRG';
const _pwd = 'pwd0123456789012345678901';
const _fp = 'AA:BB:CC';

const _offerText = '''
v=0
o=- 123 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1 2
m=audio 9 UDP/TLS/RTP/SAVPF 111 9
a=mid:0
a=setup:actpass
a=sendrecv
a=rtpmap:111 opus/48000/2
a=fmtp:111 minptime=10
a=rtcp-fb:111 transport-cc
a=rtpmap:9 G722/8000
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
m=video 9 UDP/TLS/RTP/SAVPF 96 97
a=mid:1
a=setup:actpass
a=sendonly
a=rtpmap:96 vp8/90000
a=rtcp-fb:96 nack
a=rtpmap:97 AV1/90000
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
a=mid:2
a=setup:actpass
a=sctp-port:5000
''';

void main() {
  test('buildDataChannelSdp offer snapshot', () {
    final sdp = SdpBuilder.buildDataChannelSdp(
      ufrag: _ufrag, password: _pwd, fingerprint: _fp,
      isOffer: true, sctpPort: 5000,
      localIp: '192.168.1.10', localPort: 40000,
    ).build();
    expect(_normalize(sdp), _dataChannelOffer);
  });

  test('buildDataChannelSdp answer snapshot (no host candidate)', () {
    final sdp = SdpBuilder.buildDataChannelSdp(
      ufrag: _ufrag, password: _pwd, fingerprint: _fp,
      isOffer: false, sctpPort: 5000,
    ).build();
    expect(_normalize(sdp), _dataChannelAnswer);
  });

  test('buildMediaSdp offer snapshot (audio ssrc + recvonly video)', () {
    final sdp = SdpBuilder.buildMediaSdp(
      ufrag: _ufrag, password: _pwd, fingerprint: _fp, isOffer: true,
      tracks: const [
        MediaTrack(type: 'audio', senderSsrc: 1111, codecs: [
          RtpCodec(payloadType: 111, name: 'opus', clockRate: 48000,
            channels: 2, fmtpParams: 'minptime=10;useinbandfec=1',
            rtcpFb: ['transport-cc']),
        ]),
        MediaTrack(type: 'video', direction: 'recvonly', codecs: [
          RtpCodec(payloadType: 96, name: 'VP8', clockRate: 90000,
            rtcpFb: ['nack', 'nack pli', 'goog-remb']),
        ]),
      ],
      localIp: '192.168.1.10', localPort: 40000,
    ).build();
    expect(_normalize(sdp), _mediaOffer);
  });

  test('buildAnswerFromOffer snapshot (audio+video+datachannel bundle)', () {
    final offer = SdpParser.parse(_offerText).value;
    final sdp = SdpBuilder.buildAnswerFromOffer(
      remoteOffer: offer,
      ufrag: _ufrag, password: _pwd, fingerprint: _fp,
      localIp: '192.168.1.10', localPort: 40000,
      localSenderSsrcs: const {'audio': 2222},
    ).build();
    expect(_normalize(sdp), _answerFromOffer);
  });

  test('buildAnswerFromOffer snapshot (unsupported codec rejects m-line)', () {
    final offer = SdpParser.parse('''
v=0
o=- 123 2 IN IP4 127.0.0.1
s=-
m=video 9 UDP/TLS/RTP/SAVPF 97
a=mid:0
a=rtpmap:97 AV1/90000
''').value;
    final sdp = SdpBuilder.buildAnswerFromOffer(
      remoteOffer: offer,
      ufrag: _ufrag, password: _pwd, fingerprint: _fp,
    ).build();
    expect(_normalize(sdp), _rejectedMLineAnswer);
  });
}
