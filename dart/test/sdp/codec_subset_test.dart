/// Exhaustive codec-subset test: for each of the 2^4 − 1 = 15 non-empty
/// subsets of {VP8, VP9, H264, Opus} (registration order fixed to that
/// canonical sequence), check that both the Offer and the Answer SDP
/// expose exactly those codecs in that order.
library;

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

const _vp8 = RtpCodec(payloadType: 96, name: 'VP8', clockRate: 90000);
const _vp9 = RtpCodec(payloadType: 98, name: 'VP9', clockRate: 90000);
const _h264 = RtpCodec(
  payloadType: 102,
  name: 'H264',
  clockRate: 90000,
  fmtpParams: 'level-asymmetry-allowed=1;packetization-mode=1;'
      'profile-level-id=42e01f',
);
const _opus =
    RtpCodec(payloadType: 111, name: 'opus', clockRate: 48000, channels: 2);

const _allCodecs = [_vp8, _vp9, _h264, _opus];

bool _isAudio(RtpCodec c) => c.name == 'opus';

/// 15 non-empty subsets of [_allCodecs], each preserving the canonical
/// `[VP8, VP9, H264, Opus]` order.
Iterable<List<RtpCodec>> _nonEmptySubsets() sync* {
  for (var mask = 1; mask < (1 << _allCodecs.length); mask++) {
    final subset = <RtpCodec>[];
    for (var i = 0; i < _allCodecs.length; i++) {
      if ((mask & (1 << i)) != 0) subset.add(_allCodecs[i]);
    }
    yield subset;
  }
}

/// `m= line PT order` → `codec-name order` via the rtpmap attributes.
List<String> _codecOrderOf(SdpMediaDescription m) {
  final ptToName = <String, String>{};
  for (final line in m.getAll('rtpmap')) {
    // "<pt> <name>/<rate>[/<channels>]"
    final sp = line.indexOf(' ');
    if (sp < 0) continue;
    final pt = line.substring(0, sp);
    final spec = line.substring(sp + 1);
    final slash = spec.indexOf('/');
    ptToName[pt] = slash < 0 ? spec : spec.substring(0, slash);
  }
  return [for (final pt in m.formats) ptToName[pt] ?? '?'];
}

void main() {
  final subsets = _nonEmptySubsets().toList();
  assert(subsets.length == 15, '2^4 - 1 = 15, got ${subsets.length}');

  for (final subset in subsets) {
    final video = [for (final c in subset) if (!_isAudio(c)) c];
    final audio = [for (final c in subset) if (_isAudio(c)) c];
    final label = subset.map((c) => c.name).join(',');
    final expectedVideoOrder = [for (final c in video) c.name];
    final expectedAudioOrder = [for (final c in audio) c.name];

    group('subset [$label]', () {
      late MediaEngine engine;
      setUp(() {
        engine = MediaEngine(videoCodecs: video, audioCodecs: audio);
      });

      test('Offer SDP advertises exactly the registered codecs in order',
          () async {
        final pc = PeerConnection(
          configuration: const PeerConnectionConfiguration(),
          mediaEngine: engine,
        );
        if (audio.isNotEmpty) pc.addTransceiver('audio');
        if (video.isNotEmpty) pc.addTransceiver('video');
        final offer = await pc.createOffer();
        final parsed = SdpParser.parse(offer.sdp).value;

        if (video.isNotEmpty) {
          final m = parsed.media.firstWhere((m) => m.type == 'video');
          expect(_codecOrderOf(m), equals(expectedVideoOrder),
              reason: 'video m= line should expose MediaEngine.videoCodecs '
                  'in their registration order');
        } else {
          expect(parsed.media.any((m) => m.type == 'video'), isFalse,
              reason: 'no video transceiver was added; offer should not '
                  'emit a video m= line');
        }
        if (audio.isNotEmpty) {
          final m = parsed.media.firstWhere((m) => m.type == 'audio');
          expect(_codecOrderOf(m), equals(expectedAudioOrder),
              reason: 'audio m= line should expose MediaEngine.audioCodecs '
                  'in their registration order');
        } else {
          expect(parsed.media.any((m) => m.type == 'audio'), isFalse,
              reason: 'no audio transceiver was added; offer should not '
                  'emit an audio m= line');
        }

        await pc.close();
      });

      // RFC 3264 §6.1: the answerer reflects the codec order from the
      // offer. Both peers register the same MediaEngine here so the answer
      // ends up in the same canonical order.
      test('Answer SDP advertises exactly the registered codecs in order',
          () async {
        final offerer = PeerConnection(
          configuration: const PeerConnectionConfiguration(),
          mediaEngine: engine,
        );
        if (audio.isNotEmpty) offerer.addTransceiver('audio');
        if (video.isNotEmpty) offerer.addTransceiver('video');
        final offer = await offerer.createOffer();
        await offerer.setLocalDescription(offer);

        final answerer = PeerConnection(
          configuration: const PeerConnectionConfiguration(),
          mediaEngine: engine,
        );
        if (audio.isNotEmpty) {
          answerer.addTransceiver('audio', direction: 'sendrecv');
        }
        if (video.isNotEmpty) {
          answerer.addTransceiver('video', direction: 'sendrecv');
        }
        await answerer.setRemoteDescription(offer);
        final answer = await answerer.createAnswer();
        final parsed = SdpParser.parse(answer.sdp).value;

        if (video.isNotEmpty) {
          final m = parsed.media.firstWhere((m) => m.type == 'video');
          expect(_codecOrderOf(m), equals(expectedVideoOrder),
              reason: 'video m= line in answer should mirror the offer '
                  '(which itself follows MediaEngine.videoCodecs)');
        } else {
          expect(parsed.media.any((m) => m.type == 'video'), isFalse,
              reason: 'no video on either side; answer should not emit a '
                  'video m= line');
        }
        if (audio.isNotEmpty) {
          final m = parsed.media.firstWhere((m) => m.type == 'audio');
          expect(_codecOrderOf(m), equals(expectedAudioOrder),
              reason: 'audio m= line in answer should mirror the offer '
                  '(which itself follows MediaEngine.audioCodecs)');
        } else {
          expect(parsed.media.any((m) => m.type == 'audio'), isFalse,
              reason: 'no audio on either side; answer should not emit an '
                  'audio m= line');
        }

        await offerer.close();
        await answerer.close();
      });
    });
  }
}
