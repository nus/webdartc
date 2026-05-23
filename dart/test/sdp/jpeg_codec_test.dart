/// SDP-level tests for the opt-in JPEG (RFC 2435) video codec.
library;

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('MediaEngine.jpegVideoCodec', () {
    test('not part of defaultVideoCodecs', () {
      expect(MediaEngine.defaultVideoCodecs, isNot(contains(
          predicate<RtpCodec>((c) => c.name == 'JPEG'))));
    });

    test('uses static payload type 26 with 90 kHz clock', () {
      expect(MediaEngine.jpegVideoCodec.payloadType, 26);
      expect(MediaEngine.jpegVideoCodec.clockRate, 90000);
      expect(MediaEngine.jpegVideoCodec.name, 'JPEG');
    });

    test('appears in offer SDP when opted in', () async {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        mediaEngine: const MediaEngine(
          videoCodecs: [MediaEngine.jpegVideoCodec],
          audioCodecs: [],
        ),
      );
      addTearDown(pc.close);
      pc.addTransceiver('video', preferredCodecs: ['JPEG']);
      final offer = await pc.createOffer();
      expect(offer.sdp, contains('a=rtpmap:26 JPEG/90000'));
      // m= line lists PT 26 as the (only) format.
      final m = SdpParser.parse(offer.sdp).value.media.single;
      expect(m.formats, ['26']);
    });

    test('answerer matching JPEG round-trips PT 26', () async {
      final offerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        mediaEngine: const MediaEngine(
          videoCodecs: [MediaEngine.jpegVideoCodec],
          audioCodecs: [],
        ),
      );
      addTearDown(offerer.close);
      offerer.addTransceiver('video', preferredCodecs: ['JPEG']);
      final offer = await offerer.createOffer();
      await offerer.setLocalDescription(offer);

      final answerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        mediaEngine: const MediaEngine(
          videoCodecs: [MediaEngine.jpegVideoCodec],
          audioCodecs: [],
        ),
      );
      addTearDown(answerer.close);
      answerer.addTransceiver('video', preferredCodecs: ['JPEG']);
      await answerer.setRemoteDescription(offer);
      final answer = await answerer.createAnswer();
      expect(answer.sdp, contains('a=rtpmap:26 JPEG/90000'));
      final m = SdpParser.parse(answer.sdp).value.media.single;
      expect(m.formats, ['26']);
    });

    test('answerer without JPEG drops it (matches what browsers do)', () async {
      // Simulates the Chrome/Firefox/Safari behaviour: peer offers JPEG,
      // the receiver's codec catalog doesn't include it, the m= line
      // ends up with selectedFormats empty → port=0 reject.
      final offerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        mediaEngine: const MediaEngine(
          videoCodecs: [MediaEngine.jpegVideoCodec],
          audioCodecs: [],
        ),
      );
      addTearDown(offerer.close);
      offerer.addTransceiver('video', preferredCodecs: ['JPEG']);
      final offer = await offerer.createOffer();
      await offerer.setLocalDescription(offer);

      final answerer = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        // Default catalog excludes JPEG.
      );
      addTearDown(answerer.close);
      await answerer.setRemoteDescription(offer);
      final answer = await answerer.createAnswer();
      final m = SdpParser.parse(answer.sdp).value.media.single;
      expect(m.port, 0,
          reason: 'm-line should be rejected when no common codec is found');
    });

    test('mixed catalog keeps both JPEG and VP8', () async {
      final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration(),
        mediaEngine: MediaEngine(
          videoCodecs: [
            MediaEngine.jpegVideoCodec,
            ...MediaEngine.defaultVideoCodecs,
          ],
          audioCodecs: const [],
        ),
      );
      addTearDown(pc.close);
      pc.addTransceiver('video');
      final offer = await pc.createOffer();
      expect(offer.sdp, contains('a=rtpmap:26 JPEG/90000'));
      expect(offer.sdp, contains('a=rtpmap:96 VP8/90000'));
      // JPEG is listed first because it was registered first.
      final m = SdpParser.parse(offer.sdp).value.media.single;
      expect(m.formats.first, '26');
    });
  });
}
