/// `MediaEngine.forPlatform()` narrows the default codec list to what the
/// platform can encode + decode. Host-runnable: the per-codec availability is
/// driven through the `debugSetPlatformCodecAvailability` test seam so the SDP
/// gate can be exercised without an Android device.
library;

import 'package:test/test.dart';
import 'package:webdartc/codec/platform_codecs.dart';
import 'package:webdartc/api/media_engine.dart';

void main() {
  tearDown(() {
    // Clear any forced values so each test re-probes (true on the host).
    for (final c in ['vp8', 'h264', 'opus', 'vp9']) {
      debugSetPlatformCodecAvailability(c, null);
    }
  });

  test('with everything available, equals the full defaults', () {
    final e = MediaEngine.forPlatform();
    expect(e.videoCodecNames, MediaEngine.defaultVideoCodecs.map((c) => c.name));
    expect(e.audioCodecNames, MediaEngine.defaultAudioCodecs.map((c) => c.name));
  });

  test('an unavailable codec is dropped from the advertised list', () {
    debugSetPlatformCodecAvailability('opus', false);

    final e = MediaEngine.forPlatform();
    // Opus is the only default audio codec → audio list becomes empty.
    expect(e.audioCodecs, isEmpty);
    // Video is untouched (VP8 + H.264 still advertised).
    expect(e.videoCodecNames, containsAll(['VP8', 'H264']));
  });

  test('dropping one video codec keeps the rest', () {
    debugSetPlatformCodecAvailability('vp8', false);

    final e = MediaEngine.forPlatform();
    expect(e.videoCodecNames, isNot(contains('VP8')));
    expect(e.videoCodecNames, contains('H264'));
    expect(e.audioCodecNames, contains('opus'));
  });

  test('a device without a VP9 MediaCodec drops only VP9', () {
    debugSetPlatformCodecAvailability('vp9', false);

    final e = MediaEngine.forPlatform();
    expect(e.videoCodecNames, isNot(contains('VP9')));
    expect(e.videoCodecNames, containsAll(['VP8', 'H264']));
    expect(e.audioCodecNames, contains('opus'));
  });
}
