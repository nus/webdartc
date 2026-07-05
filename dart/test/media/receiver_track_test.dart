import 'dart:typed_data';

import 'package:webdartc/src/media/receiver_track.dart';
import 'package:webdartc/src/media/video_frame.dart';
import 'package:webdartc/src/media/audio_data.dart';
import 'package:webdartc/src/media/media_stream_track.dart';
import 'package:test/test.dart';

VideoFrame _frame(int ts) => VideoFrame(
      format: VideoPixelFormat.i420,
      codedWidth: 4,
      codedHeight: 4,
      timestamp: ts,
      data: Uint8List(24),
    );

AudioData _audio(int ts, {int len = 8}) => AudioData(
      format: AudioSampleFormat.s16,
      sampleRate: 48000,
      numberOfChannels: 1,
      numberOfFrames: len ~/ 2,
      timestamp: ts,
      data: Uint8List.fromList(List.filled(len, 0x7F)),
    );

void main() {
  group('ReceiverVideoTrack', () {
    test('delivers frames to a subscriber', () async {
      final track = ReceiverVideoTrack(id: 'v1');
      expect(track.kind, 'video');
      expect(track.readyState, MediaStreamTrackState.live);

      final got = <int>[];
      final sub = track.onVideoFrame.listen((f) => got.add(f.timestamp));
      await Future<void>.delayed(Duration.zero);
      track.deliverFrame(_frame(1));
      track.deliverFrame(_frame(2));
      await Future<void>.delayed(Duration.zero);
      expect(got, [1, 2]);
      await sub.cancel();
    });

    test('onActivate fires on first listener, onDeactivate on last cancel',
        () async {
      final track = ReceiverVideoTrack(id: 'v1');
      var activated = 0;
      var deactivated = 0;
      track.onActivate = () => activated++;
      track.onDeactivate = () => deactivated++;

      final sub = track.onVideoFrame.listen((_) {});
      await Future<void>.delayed(Duration.zero);
      expect(activated, 1);
      expect(deactivated, 0);

      await sub.cancel();
      expect(deactivated, 1);
    });

    test('drops frames when disabled', () async {
      final track = ReceiverVideoTrack(id: 'v1');
      final got = <int>[];
      track.onVideoFrame.listen((f) => got.add(f.timestamp));
      await Future<void>.delayed(Duration.zero);

      track.enabled = false;
      track.deliverFrame(_frame(1));
      track.enabled = true;
      track.deliverFrame(_frame(2));
      await Future<void>.delayed(Duration.zero);
      expect(got, [2]);
    });

    test('stop ends the track and fires onEnded', () async {
      final track = ReceiverVideoTrack(id: 'v1');
      var ended = false;
      track.onEnded.listen((_) => ended = true);
      track.stop();
      await Future<void>.delayed(Duration.zero);
      expect(ended, isTrue);
      expect(track.readyState, MediaStreamTrackState.ended);
      // Delivering after stop is a no-op (no throw).
      track.deliverFrame(_frame(9));
    });

    test('onAudioData throws on a video track', () {
      final track = ReceiverVideoTrack(id: 'v1');
      expect(() => track.onAudioData, throwsUnsupportedError);
    });

    test('clone shares the source frames with independent enabled', () async {
      final track = ReceiverVideoTrack(id: 'v1');
      final clone = track.clone();
      expect(clone.id, isNot('v1'));

      final orig = <int>[];
      final cl = <int>[];
      track.onVideoFrame.listen((f) => orig.add(f.timestamp));
      clone.onVideoFrame.listen((f) => cl.add(f.timestamp));
      await Future<void>.delayed(Duration.zero);

      track.deliverFrame(_frame(1));
      await Future<void>.delayed(Duration.zero);
      expect(orig, [1]);
      expect(cl, [1]); // clone receives the same frame
    });
  });

  group('ReceiverAudioTrack', () {
    test('delivers audio to a subscriber', () async {
      final track = ReceiverAudioTrack(id: 'a1');
      expect(track.kind, 'audio');
      final got = <int>[];
      track.onAudioData.listen((d) => got.add(d.timestamp));
      await Future<void>.delayed(Duration.zero);
      track.deliverAudio(_audio(1));
      await Future<void>.delayed(Duration.zero);
      expect(got, [1]);
    });

    test('emits silence (not a gap) when disabled', () async {
      final track = ReceiverAudioTrack(id: 'a1');
      final got = <AudioData>[];
      track.onAudioData.listen(got.add);
      await Future<void>.delayed(Duration.zero);

      track.enabled = false;
      track.deliverAudio(_audio(1, len: 8));
      await Future<void>.delayed(Duration.zero);
      expect(got.length, 1); // frame still emitted, but zeroed
      expect(got.first.data, everyElement(0));
      expect(got.first.numberOfFrames, 4);
    });

    test('onVideoFrame throws on an audio track', () {
      final track = ReceiverAudioTrack(id: 'a1');
      expect(() => track.onVideoFrame, throwsUnsupportedError);
    });
  });
}
