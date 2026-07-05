@Tags(['native'])
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/audio_codec.dart';
import 'package:webdartc/codec/opus/opus_codec.dart';
import 'package:webdartc/codec/video_codec.dart';
import 'package:webdartc/codec/vp8/vp8_codec.dart';
import 'package:webdartc/codec/vp9/vp9_codec.dart';
import 'package:webdartc/media/audio_data.dart';
import 'package:webdartc/media/fake_audio_source.dart';
import 'package:webdartc/codec/codec_support.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/media/receive_pipeline.dart';
import 'package:webdartc/media/receiver_track.dart';
import 'package:webdartc/media/video_frame.dart';
import 'package:webdartc/rtp/packetizer.dart';
import 'package:webdartc/rtp/parser.dart';

/// Encode [n] frames with [codec] and return their packetized RTP payloads
/// (with the marker flag) plus the source key/delta classification per frame.
Future<List<(List<(Uint8List, bool)> parts, bool isKey)>> _encodeVideo(
    String codec, int n) async {
  final chunks = <EncodedVideoChunk>[];
  final encoder = VideoEncoder(
    output: (c, _) => chunks.add(c),
    error: (e) => fail('encoder error: $e'),
  );
  encoder.configure(VideoEncoderConfig(
      codec: codec, width: 160, height: 120, framerate: 30));
  final src = FakeVideoSource(width: 160, height: 120, framerate: 30);
  for (var i = 0; i < n; i++) {
    encoder.encode(src.frameAt(1_700_000_000_000 + i * 33),
        const VideoEncoderEncodeOptions());
  }
  await encoder.flush();
  encoder.close();

  final packetizer = videoPacketizerFor(codec)!;
  return [
    for (final c in chunks)
      (
        packetizer.packetize(c.data,
            isKeyFrame: c.type == EncodedVideoChunkType.key),
        c.type == EncodedVideoChunkType.key,
      ),
  ];
}

RtpPacket _rtp(Uint8List payload, int seq, bool marker, int ts) => RtpPacket(
      payloadType: 96,
      sequenceNumber: seq & 0xFFFF,
      timestamp: ts,
      ssrc: 0xABCD,
      marker: marker,
      payload: payload,
    );

void main() {
  test('tryCreate returns null for an unsupported codec', () {
    final p = ReceivePipeline.tryCreate(
        kind: 'video', codecKey: 'av1', clockRate: 90000, channels: 0);
    expect(p, isNull);
  });

  test('tryCreate returns null when no decoder is registered', () {
    // 'h264' has a depacketizer but no decoder registered in this test run.
    final p = ReceivePipeline.tryCreate(
        kind: 'video', codecKey: 'h264', clockRate: 90000, channels: 0);
    expect(p, isNull);
  });

  group('VP8 video pipeline', () {
    setUpAll(registerVp8Codec);

    test('decodes frames pushed as RTP and emits them on the track', () async {
      final encoded = await _encodeVideo('vp8', 5);

      final p = ReceivePipeline.tryCreate(
          kind: 'video', codecKey: 'vp8', clockRate: 90000, channels: 0)!;
      expect(p.track, isA<ReceiverVideoTrack>());

      final frames = <VideoFrame>[];
      final sub = p.track.onVideoFrame.listen(frames.add);
      await Future<void>.delayed(Duration.zero); // let onActivate run
      expect(p.isActive, isTrue);

      var seq = 0;
      var arrival = 0;
      for (final (parts, _) in encoded) {
        for (final (payload, marker) in parts) {
          p.add(_rtp(payload, seq++, marker, 3000 * seq), arrival);
        }
        arrival += 1000;
      }
      // Drain well past the playout delay so all buffered packets release.
      p.tick(arrival + 1_000_000);
      await Future<void>.delayed(Duration.zero);

      expect(frames, isNotEmpty);
      expect(frames.first.codedWidth, 160);
      expect(frames.first.codedHeight, 120);
      await sub.cancel();
      p.close();
    });

    test('keyframe gate drops delta packets until the first keyframe',
        () async {
      final encoded = await _encodeVideo('vp8', 4);
      // Frame 0 is the keyframe; frames 1..3 are deltas.
      final p = ReceivePipeline.tryCreate(
          kind: 'video', codecKey: 'vp8', clockRate: 90000, channels: 0)!;
      final frames = <VideoFrame>[];
      final sub = p.track.onVideoFrame.listen(frames.add);
      await Future<void>.delayed(Duration.zero);

      var seq = 0;
      // Feed only the delta frames first (skip the keyframe).
      for (var i = 1; i < encoded.length; i++) {
        for (final (payload, marker) in encoded[i].$1) {
          p.add(_rtp(payload, seq++, marker, 3000 * (seq + 1)), 0);
        }
      }
      p.tick(2_000_000);
      await Future<void>.delayed(Duration.zero);
      expect(frames, isEmpty, reason: 'no keyframe yet → nothing decodes');

      // Now feed the keyframe (frame 0). Use higher seqs so they release next.
      for (final (payload, marker) in encoded[0].$1) {
        p.add(_rtp(payload, seq++, marker, 99999), 2_000_000);
      }
      p.tick(5_000_000);
      await Future<void>.delayed(Duration.zero);
      expect(frames, isNotEmpty, reason: 'keyframe arrived → decodes');
      await sub.cancel();
      p.close();
    });

    test('retransmits PLI while no keyframe has decoded', () {
      var pliCount = 0;
      final p = ReceivePipeline.tryCreate(
          kind: 'video',
          codecKey: 'vp8',
          clockRate: 90000,
          channels: 0,
          requestKeyframe: () => pliCount++)!;
      // Activate without a real consumer by subscribing.
      final sub = p.track.onVideoFrame.listen((_) {});
      // First tick sets the baseline (no PLI yet).
      p.tick(0);
      expect(pliCount, 0);
      // After each retransmit interval (1s), one PLI fires, capped at 5.
      for (var t = 1; t <= 8; t++) {
        p.tick(t * 1_000_000);
      }
      expect(pliCount, 5); // _pliMaxRetries
      sub.cancel();
      p.close();
    });
  });

  group('VP9 video pipeline', () {
    setUpAll(registerVp9Codec);

    test('decodes frames pushed as RTP and emits them on the track', () async {
      final encoded = await _encodeVideo('vp9', 5);

      final p = ReceivePipeline.tryCreate(
          kind: 'video', codecKey: 'vp9', clockRate: 90000, channels: 0)!;
      expect(p.track, isA<ReceiverVideoTrack>());

      final frames = <VideoFrame>[];
      final sub = p.track.onVideoFrame.listen(frames.add);
      await Future<void>.delayed(Duration.zero); // let onActivate run
      expect(p.isActive, isTrue);

      var seq = 0;
      var arrival = 0;
      for (final (parts, _) in encoded) {
        for (final (payload, marker) in parts) {
          p.add(_rtp(payload, seq++, marker, 3000 * seq), arrival);
        }
        arrival += 1000;
      }
      p.tick(arrival + 1_000_000);
      await Future<void>.delayed(Duration.zero);

      expect(frames, isNotEmpty);
      expect(frames.first.codedWidth, 160);
      expect(frames.first.codedHeight, 120);
      await sub.cancel();
      p.close();
    });
  });

  group('Opus audio pipeline', () {
    setUpAll(registerOpusCodec);

    test('decodes Opus RTP into AudioData on the track', () async {
      // Encode a few Opus frames from a fake tone.
      final chunks = <EncodedAudioChunk>[];
      final encoder = AudioEncoder(
        output: (c, _) => chunks.add(c),
        error: (e) => fail('opus encoder error: $e'),
      );
      encoder.configure(const AudioEncoderConfig(
          codec: AudioCodecName.opus, sampleRate: 48000, numberOfChannels: 2));
      final src = FakeAudioSource(sampleRate: 48000, numberOfChannels: 2);
      var fed = 0;
      await for (final data in src.start()) {
        encoder.encode(data);
        if (++fed >= 5) break;
      }
      await encoder.flush();
      encoder.close();
      expect(chunks, isNotEmpty);

      final p = ReceivePipeline.tryCreate(
          kind: 'audio', codecKey: 'opus', clockRate: 48000, channels: 2)!;
      final out = <AudioData>[];
      final sub = p.track.onAudioData.listen(out.add);
      await Future<void>.delayed(Duration.zero);
      expect(p.isActive, isTrue);

      final packetizer = OpusPacketizer();
      var seq = 0;
      var arrival = 0;
      for (final c in chunks) {
        final parts = packetizer.packetize(c.data, isKeyFrame: true);
        for (final (payload, marker) in parts) {
          p.add(_rtp(payload, seq++, marker, 960 * seq), arrival);
        }
        arrival += 20000;
      }
      p.tick(arrival + 1_000_000);
      await Future<void>.delayed(Duration.zero);
      expect(out, isNotEmpty);
      expect(out.first.sampleRate, 48000);
      await sub.cancel();
      p.close();
    });
  });
}
