/// Exhaustive codec-subset test: for each of the 2^4 − 1 = 15 non-empty
/// subsets of {VP8, VP9, H264, Opus} (registration order fixed to that
/// canonical sequence), check that both the Offer and the Answer SDP
/// expose exactly those codecs in that order.
library;

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

const _vp9 = RtpCodec(payloadType: 98, name: 'VP9', clockRate: 90000);

/// Canonical video catalog: `MediaEngine.defaultVideoCodecs` (VP8, H264)
/// with VP9 spliced between them to match the canonical
/// [VP8, VP9, H264] order.
final _videoCatalog = <RtpCodec>[
  MediaEngine.defaultVideoCodecs[0], // VP8
  _vp9,
  MediaEngine.defaultVideoCodecs[1], // H264
];
const _audioCatalog = MediaEngine.defaultAudioCodecs;
final _allCodecs = [..._videoCatalog, ..._audioCatalog];

/// 15 non-empty subsets of `_allCodecs`, each preserving the canonical
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

void _expectMatch(
  SdpSessionDescription parsed,
  List<RtpCodec> video,
  List<RtpCodec> audio, {
  required String which,
}) {
  for (final (kind, codecs) in [('video', video), ('audio', audio)]) {
    final expected = [for (final c in codecs) c.name];
    final present = parsed.media.where((m) => m.type == kind).toList();
    if (codecs.isEmpty) {
      expect(present, isEmpty,
          reason: 'no $kind transceiver was added; $which should not emit '
              'a $kind m= line');
    } else {
      expect(_codecOrderOf(present.single), equals(expected),
          reason: '$kind m= line in $which should expose the registered '
              'codecs in their registration order');
    }
  }
}

void main() {
  final subsets = _nonEmptySubsets().toList();
  assert(subsets.length == 15, '2^4 - 1 = 15, got ${subsets.length}');

  for (final subset in subsets) {
    final video = [for (final c in subset) if (_videoCatalog.contains(c)) c];
    final audio = [for (final c in subset) if (_audioCatalog.contains(c)) c];
    final label = subset.map((c) => c.name).join(',');
    final engine = MediaEngine(videoCodecs: video, audioCodecs: audio);

    group('subset [$label]', () {
      test('Offer SDP advertises exactly the registered codecs in order',
          () async {
        final pc = PeerConnection(
          configuration: const PeerConnectionConfiguration(),
          mediaEngine: engine,
        );
        addTearDown(pc.close);
        if (audio.isNotEmpty) pc.addTransceiver('audio');
        if (video.isNotEmpty) pc.addTransceiver('video');
        final offer = await pc.createOffer();
        _expectMatch(SdpParser.parse(offer.sdp).value, video, audio,
            which: 'offer');
      });

      // RFC 3264 §6.1: the answerer reflects the codec order from the
      // offer. Both peers register the same MediaEngine here, so the
      // answer ends up in the same canonical order.
      test('Answer SDP advertises exactly the registered codecs in order',
          () async {
        final offerer = PeerConnection(
          configuration: const PeerConnectionConfiguration(),
          mediaEngine: engine,
        );
        addTearDown(offerer.close);
        if (audio.isNotEmpty) offerer.addTransceiver('audio');
        if (video.isNotEmpty) offerer.addTransceiver('video');
        final offer = await offerer.createOffer();
        await offerer.setLocalDescription(offer);

        final answerer = PeerConnection(
          configuration: const PeerConnectionConfiguration(),
          mediaEngine: engine,
        );
        addTearDown(answerer.close);
        if (audio.isNotEmpty) {
          answerer.addTransceiver('audio', direction: 'sendrecv');
        }
        if (video.isNotEmpty) {
          answerer.addTransceiver('video', direction: 'sendrecv');
        }
        await answerer.setRemoteDescription(offer);
        final answer = await answerer.createAnswer();
        _expectMatch(SdpParser.parse(answer.sdp).value, video, audio,
            which: 'answer');
      });
    });
  }
}
