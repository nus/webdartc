/// VP9 wire-format round-trip: encoder → RTP packetizer → depacketizer →
/// decoder over a small MTU that forces fragmentation, plus the
/// draft-ietf-payload-vp9 descriptor invariants Chrome relies on
/// (P bit distinguishing key/delta, B/E frame boundaries).
@Tags(['native'])
library;

import 'package:test/test.dart';
import 'package:webdartc/src/codec/video_codec.dart';
import 'package:webdartc/src/codec/vp9/vp9_codec.dart';
import 'package:webdartc/src/media/fake_video_source.dart';
import 'package:webdartc/src/media/video_frame.dart';
import 'package:webdartc/src/rtp/packetizer.dart';

void main() {
  setUpAll(registerVp9Codec);

  test('encode → packetize (small MTU) → depacketize → decode reassembles '
      'byte-identical frames with the expected descriptor bits', () async {
    const width = 320, height = 240, frames = 4;

    final chunks = <EncodedVideoChunk>[];
    final encoder = VideoEncoder(
      output: (c, _) => chunks.add(c),
      error: (e) => fail('encoder error: $e'),
    );
    encoder.configure(const VideoEncoderConfig(
      codec: VideoCodecName.vp9,
      width: width,
      height: height,
      bitrate: 400000,
      framerate: 30,
    ));

    final src = FakeVideoSource(width: width, height: height, framerate: 30);
    for (var i = 0; i < frames; i++) {
      encoder.encode(src.frameAt(1_700_000_000_000 + i * 33));
    }
    await encoder.flush();
    encoder.close();

    expect(chunks, hasLength(frames));
    expect(chunks[0].type, EncodedVideoChunkType.key);
    expect(chunks[1].type, EncodedVideoChunkType.delta);

    final packetizer = Vp9Packetizer(maxPayloadSize: 200);
    final depacketizer = Vp9Depacketizer();
    final reassembled = <EncodedVideoChunk>[];

    for (final chunk in chunks) {
      final isKey = chunk.type == EncodedVideoChunkType.key;
      final parts = packetizer.packetize(chunk.data, isKeyFrame: isKey);
      expect(parts, isNotEmpty);
      if (isKey) {
        // A 320x240 keyframe is always well past 200 bytes; delta frames
        // from the static fake source can fit in a single packet.
        expect(parts.length, greaterThan(1),
            reason: 'MTU 200 must fragment the keyframe');
      }

      final first = parts.first.$1;
      expect(first[0] & 0x80, 0x80, reason: 'I: picture ID present');
      expect(first[0] & 0x40, isKey ? 0x00 : 0x40,
          reason: 'P bit must be clear exactly on keyframes');
      expect(first[0] & 0x08, 0x08, reason: 'B on the first fragment');
      expect(parts.last.$1[0] & 0x04, 0x04, reason: 'E on the last fragment');
      expect(parts.last.$2, isTrue, reason: 'marker on the last fragment');

      EncodedVideoChunk? assembled;
      for (final (payload, marker) in parts) {
        final out = depacketizer.depacketize(payload,
            marker: marker, timestamp: chunk.timestamp);
        if (out != null) assembled = out;
      }
      expect(assembled, isNotNull);
      reassembled.add(assembled!);
    }

    for (var i = 0; i < chunks.length; i++) {
      expect(reassembled[i].data, chunks[i].data,
          reason: 'frame $i bytes must match exactly');
      expect(reassembled[i].type, chunks[i].type,
          reason: 'frame $i key/delta classification must match');
    }

    // The reassembled stream must still decode.
    final decoded = <VideoFrame>[];
    final decoder = VideoDecoder(
      output: decoded.add,
      error: (e) => fail('decoder error: $e'),
    );
    decoder.configure(const VideoDecoderConfig(
      codec: VideoCodecName.vp9,
      codedWidth: width,
      codedHeight: height,
    ));
    for (final chunk in reassembled) {
      decoder.decode(chunk);
    }
    await decoder.flush();
    decoder.close();

    expect(decoded, hasLength(frames));
    expect(decoded.first.codedWidth, width);
    expect(decoded.first.codedHeight, height);
  });
}
