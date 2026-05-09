import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('MediaEngine value semantics', () {
    test('default constructor exposes VP8 + H.264 video and Opus audio', () {
      const m = MediaEngine();
      expect(m.videoCodecNames, equals(['VP8', 'H264']));
      expect(m.audioCodecNames, equals(['opus']));
    });

    test('empty engine advertises nothing', () {
      const m = MediaEngine.empty;
      expect(m.videoCodecs, isEmpty);
      expect(m.audioCodecs, isEmpty);
    });

    test('extending defaults via spread keeps base order', () {
      const av1 = RtpCodec(
          payloadType: 45, name: 'AV1', clockRate: 90000);
      const m = MediaEngine(
        videoCodecs: [...MediaEngine.defaultVideoCodecs, av1],
      );
      expect(m.videoCodecNames, equals(['VP8', 'H264', 'AV1']));
    });

    test('resolveVideoCodecs(null) returns the full list', () {
      const m = MediaEngine();
      expect(m.resolveVideoCodecs(null).map((c) => c.name).toList(),
          equals(['VP8', 'H264']));
    });

    test('resolveVideoCodecs filters and reorders by preference', () {
      const m = MediaEngine();
      final r = m.resolveVideoCodecs(['H264', 'VP8']);
      expect(r.map((c) => c.name).toList(), equals(['H264', 'VP8']));
    });

    test('resolveVideoCodecs ignores unknown names silently', () {
      const m = MediaEngine();
      final r = m.resolveVideoCodecs(['VP9', 'VP8']);
      expect(r.map((c) => c.name).toList(), equals(['VP8']));
    });

    test('resolveVideoCodecs is case-insensitive on names', () {
      const m = MediaEngine();
      final r = m.resolveVideoCodecs(['vp8', 'h264']);
      expect(r.map((c) => c.name).toList(), equals(['VP8', 'H264']));
    });
  });

  group('PeerConnection wiring', () {
    test('default PC inherits the default MediaEngine', () {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      expect(pc.mediaEngine.videoCodecNames, equals(['VP8', 'H264']));
      expect(pc.mediaEngine.audioCodecNames, equals(['opus']));
    });

    test('Webdartc factory forwards a custom MediaEngine to the PC', () {
      const rtc = Webdartc(mediaEngine: MediaEngine.empty);
      final pc = rtc.createPeerConnection();
      expect(identical(pc.mediaEngine, MediaEngine.empty), isTrue);
      expect(pc.mediaEngine.audioCodecs, isEmpty);
      expect(pc.mediaEngine.videoCodecs, isEmpty);
    });
  });

  group('SDP reflects MediaEngine', () {
    test('default offer SDP advertises VP8, H.264, and Opus', () async {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      pc.addTransceiver('audio');
      pc.addTransceiver('video');
      final offer = await pc.createOffer();
      expect(offer.sdp, contains('a=rtpmap:111 opus/48000/2'));
      expect(offer.sdp, contains('a=rtpmap:96 VP8/90000'));
      expect(offer.sdp, contains('a=rtpmap:102 H264/90000'));
      await pc.close();
    });

    test('custom MediaEngine restricts the offer to its codec list', () async {
      const onlyOpus = MediaEngine(
        videoCodecs: [],
        audioCodecs: MediaEngine.defaultAudioCodecs,
      );
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        mediaEngine: onlyOpus,
      );
      pc.addTransceiver('audio');
      pc.addTransceiver('video');
      final offer = await pc.createOffer();
      expect(offer.sdp, contains('a=rtpmap:111 opus/48000/2'));
      expect(offer.sdp, isNot(contains('VP8')));
      expect(offer.sdp, isNot(contains('H264')));
      await pc.close();
    });

    test('preferredCodecs filters MediaEngine output to a subset', () async {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      pc.addTransceiver('video', preferredCodecs: ['H264']);
      final offer = await pc.createOffer();
      expect(offer.sdp, contains('a=rtpmap:102 H264/90000'));
      expect(offer.sdp, isNot(contains('VP8')));
      await pc.close();
    });

    test('answer honours MediaEngine when offer asks for codecs we omit',
        () async {
      // Build an offer with VP8+H.264 from a default PC.
      final offerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      offerer.addTransceiver('video');
      final offer = await offerer.createOffer();
      await offerer.setLocalDescription(offer);

      // Answer with a MediaEngine that only knows H.264.
      const onlyH264 = MediaEngine(
        videoCodecs: [
          RtpCodec(
            payloadType: 102,
            name: 'H264',
            clockRate: 90000,
            fmtpParams: 'level-asymmetry-allowed=1;packetization-mode=1;'
                'profile-level-id=42e01f',
            rtcpFb: ['nack'],
          ),
        ],
        audioCodecs: [],
      );
      final answerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        mediaEngine: onlyH264,
      );
      await answerer.setRemoteDescription(offer);
      final answer = await answerer.createAnswer();
      expect(answer.sdp, contains('H264/90000'));
      expect(answer.sdp, isNot(contains('VP8')));

      await offerer.close();
      await answerer.close();
    });

    test('answerer sender PT matches the negotiated codec, not the offer\'s '
        'first preference', () async {
      final offerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      offerer.addTransceiver('video'); // default: VP8 + H.264 (96, 102)
      final offer = await offerer.createOffer();
      await offerer.setLocalDescription(offer);

      const onlyH264 = MediaEngine(
        videoCodecs: [
          RtpCodec(payloadType: 102, name: 'H264', clockRate: 90000),
        ],
        audioCodecs: [],
      );
      final answerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        mediaEngine: onlyH264,
      );
      answerer.addTransceiver('video', direction: 'sendrecv');
      await answerer.setRemoteDescription(offer);
      final answer = await answerer.createAnswer();
      expect(answer.sdp, contains('H264/90000'));

      final sender = answerer.getSenders().firstWhere((s) => s.kind == 'video');
      expect(sender.payloadType, equals(102),
          reason:
              'answerer must stamp RTP with the negotiated H.264 PT (102), '
              'not the offer\'s first format (96 = VP8)');

      await offerer.close();
      await answerer.close();
    });

    test('audio+video offer / video-only answerer with preferredCodecs=H264: '
        'video sender gets H.264 mid + PT, not VP8 nor audio', () async {
      final offerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      offerer.addTransceiver('audio');
      offerer.addTransceiver('video');
      final offer = await offerer.createOffer();
      await offerer.setLocalDescription(offer);

      final answerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      answerer.addTransceiver('video',
          direction: 'sendrecv', preferredCodecs: const ['H264']);
      await answerer.setRemoteDescription(offer);
      final answer = await answerer.createAnswer();

      final parsed = SdpParser.parse(answer.sdp).value;
      final video = parsed.media.firstWhere((m) => m.type == 'video');
      final audio = parsed.media.firstWhere((m) => m.type == 'audio');

      final videoCodecs = video.getAll('rtpmap').map((s) => s.split(' ').last);
      expect(videoCodecs, everyElement(startsWith('H264/')),
          reason: 'preferredCodecs=[H264] must filter VP8 out of the answer');

      final sender =
          answerer.getSenders().firstWhere((s) => s.kind == 'video');
      expect(sender.payloadType, equals(102),
          reason:
              'video sender PT must be H.264; if pairing skips past the '
              'video transceiver while looking for an audio match, the PT '
              'never gets assigned');

      // Telling the remote `sendrecv` while we have no audio sender stops
      // Chrome from routing OUR video over the same BUNDLE transport.
      expect(audio.direction, equals('recvonly'));

      await offerer.close();
      await answerer.close();
    });

    test('passthrough use case: empty backends, capability-only MediaEngine',
        () async {
      // Application registers no codec backends but still wants to negotiate
      // VP8 + Opus and access RTP packets directly.
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
      );
      pc.addTransceiver('audio');
      pc.addTransceiver('video');
      final offer = await pc.createOffer();
      // The SDP advertises codecs even though no encoder/decoder backends
      // are registered.
      expect(offer.sdp, contains('opus'));
      expect(offer.sdp, contains('VP8'));
      // pc.onRtpPacket is the passthrough surface; just check it exists.
      expect(pc.onRtpPacket, isNotNull);
      await pc.close();
    });
  });
}
