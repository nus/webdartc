/// Locks in VP8 wire-format invariants that must hold regardless of the
/// libvpx version: frame-tag bit-0 (frame_type) and the 0x9D 0x01 0x2A
/// start code that every keyframe carries (RFC 6386 §9.1).
///
/// These are spec, not implementation choices — if libvpx ever produces
/// output that violates them, callers (browsers, RTP receivers, …) will
/// reject every frame we send, and the breakage is far more expensive
/// to diagnose downstream than at the encoder.
@Tags(['native'])
library;

import 'package:test/test.dart';
import 'package:webdartc/src/codec/video_codec.dart';
import 'package:webdartc/src/codec/vp8/vp8_codec.dart';
import 'package:webdartc/src/media/fake_video_source.dart';

void main() {
  setUpAll(registerVp8Codec);

  test('keyframe frame tag has bit 0 = 0 and the 9D-01-2A start code; '
      'delta frame tag has bit 0 = 1', () async {
    const width = 320, height = 240;

    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('encoder error: $e'),
    );
    encoder.configure(const VideoEncoderConfig(
      codec: VideoCodecName.vp8,
      width: width,
      height: height,
      bitrate: 400000,
      framerate: 30,
    ));

    final src = FakeVideoSource(width: width, height: height, framerate: 30);
    for (var i = 0; i < 4; i++) {
      encoder.encode(src.frameAt(i * 33333));
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, hasLength(4));

    final key = chunks[0];
    final delta = chunks[1];
    expect(key.type, EncodedVideoChunkType.key);
    expect(delta.type, EncodedVideoChunkType.delta);

    // RFC 6386 §9.1: byte 0 bit 0 = frame_type. 0 = keyframe.
    expect(key.data[0] & 0x01, 0,
        reason: 'keyframe frame_type bit must be 0');
    expect(delta.data[0] & 0x01, 1,
        reason: 'interframe frame_type bit must be 1');

    // Keyframes only: bytes 3..5 are the fixed start code.
    expect(key.data.sublist(3, 6), [0x9D, 0x01, 0x2A],
        reason: 'VP8 keyframe must carry the 0x9D 0x01 0x2A start code');

    // RFC 6386 §9.1: bytes 6..9 encode (width, height) as 14-bit LE
    // values (the top 2 bits of each 16-bit word are scaling hints).
    final encodedWidth = (key.data[6] | (key.data[7] << 8)) & 0x3FFF;
    final encodedHeight = (key.data[8] | (key.data[9] << 8)) & 0x3FFF;
    expect(encodedWidth, width);
    expect(encodedHeight, height);
  });
}
