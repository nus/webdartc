import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

/// Minimal track for addTrack — a real capture track is platform-specific.
final class _FakeTrack extends MediaStreamTrack {
  @override
  final String id;
  @override
  final String kind;
  _FakeTrack(this.id, this.kind);
  @override
  String get label => 'fake';
  @override
  bool enabled = true;
  @override
  MediaStreamTrackState get readyState => MediaStreamTrackState.live;
  @override
  MediaStreamTrack clone() => _FakeTrack(id, kind);
  @override
  void stop() {}
  @override
  Stream<VideoFrame> get onVideoFrame => throw UnsupportedError('audio');
  @override
  Stream<AudioData> get onAudioData => const Stream<AudioData>.empty();
}

void main() {
  group('RtpTransceiverDirection', () {
    test('token round-trips', () {
      for (final token in ['sendrecv', 'sendonly', 'recvonly', 'inactive']) {
        expect(RtpTransceiverDirection.fromToken(token).sdpToken, token);
      }
    });

    test('stopped maps to inactive on the wire', () {
      expect(RtpTransceiverDirection.stopped.sdpToken, 'inactive');
    });

    test('unknown token falls back to sendrecv', () {
      expect(RtpTransceiverDirection.fromToken('bogus'),
          RtpTransceiverDirection.sendrecv);
    });

    test('negotiated direction is the local/remote intersection', () {
      const d = RtpTransceiverDirection.values;
      RtpTransceiverDirection neg(
              RtpTransceiverDirection l, RtpTransceiverDirection r) =>
          RtpTransceiverDirection.negotiated(l, r);
      // symmetric
      expect(neg(d[0], d[0]), RtpTransceiverDirection.sendrecv); // sendrecv×sendrecv
      // asymmetric, both directions usable
      expect(neg(RtpTransceiverDirection.sendonly,
          RtpTransceiverDirection.recvonly), RtpTransceiverDirection.sendonly);
      expect(neg(RtpTransceiverDirection.recvonly,
          RtpTransceiverDirection.sendonly), RtpTransceiverDirection.recvonly);
      // remote narrows us: we offer sendrecv, peer only receives → we send only
      expect(neg(RtpTransceiverDirection.sendrecv,
          RtpTransceiverDirection.recvonly), RtpTransceiverDirection.sendonly);
      expect(neg(RtpTransceiverDirection.sendrecv,
          RtpTransceiverDirection.sendonly), RtpTransceiverDirection.recvonly);
      // no overlap → inactive
      expect(neg(RtpTransceiverDirection.sendonly,
          RtpTransceiverDirection.sendonly), RtpTransceiverDirection.inactive);
      expect(neg(RtpTransceiverDirection.inactive,
          RtpTransceiverDirection.sendrecv), RtpTransceiverDirection.inactive);
    });
  });

  group('PeerConnection transceivers', () {
    late PeerConnection pc;
    setUp(() {
      pc = PeerConnection(configuration: const PeerConnectionConfiguration());
    });
    tearDown(() => pc.close());

    test('addTransceiver returns a sendrecv transceiver with a sender', () {
      final t = pc.addTransceiver('audio');
      expect(t.kind, 'audio');
      expect(t.direction, RtpTransceiverDirection.sendrecv);
      expect(t.currentDirection, isNull); // not negotiated yet
      expect(t.mid, isNull);
      expect(t.stopped, isFalse);
      expect(t.sender, isNotNull);
      expect(t.receiver, isNull);

      expect(pc.getTransceivers(), [t]);
      expect(pc.getSenders(), [t.sender]);
      expect(pc.getReceivers(), isEmpty);
    });

    test('a recvonly transceiver has no sender', () {
      final t = pc.addTransceiver('video', direction: 'recvonly');
      expect(t.direction, RtpTransceiverDirection.recvonly);
      expect(t.sender, isNull);
      expect(pc.getSenders(), isEmpty);
      expect(pc.getTransceivers(), hasLength(1));
    });

    test('addTrack creates a sendrecv transceiver carrying the track', () {
      final track = _FakeTrack('t1', 'audio');
      final sender = pc.addTrack(track);
      expect(sender.track, same(track));
      final t = pc.getTransceivers().single;
      expect(t.kind, 'audio');
      expect(t.sender, same(sender));
    });

    test('getTransceivers preserves creation order', () {
      final a = pc.addTransceiver('audio');
      final v = pc.addTransceiver('video', direction: 'recvonly');
      expect(pc.getTransceivers(), [a, v]);
    });

    test('setDirection updates the preferred direction', () {
      final t = pc.addTransceiver('audio');
      t.setDirection(RtpTransceiverDirection.inactive);
      expect(t.direction, RtpTransceiverDirection.inactive);
    });

    test('stop marks the transceiver stopped and blocks setDirection', () {
      final t = pc.addTransceiver('audio');
      t.stop();
      expect(t.stopped, isTrue);
      expect(t.direction, RtpTransceiverDirection.stopped);
      expect(t.currentDirection, RtpTransceiverDirection.stopped);
      expect(() => t.setDirection(RtpTransceiverDirection.sendrecv),
          throwsStateError);
      expect(t.stop, returnsNormally); // idempotent
    });

    test('getTransceivers returns an unmodifiable view', () {
      pc.addTransceiver('audio');
      expect(() => pc.getTransceivers().add(pc.getTransceivers().first),
          throwsUnsupportedError);
    });

    test('removeTrack detaches the track and downgrades the direction', () {
      final sender = pc.addTrack(_FakeTrack('t1', 'audio'));
      final t = pc.getTransceivers().single;
      expect(t.direction, RtpTransceiverDirection.sendrecv);

      pc.removeTrack(sender);
      expect(sender.track, isNull);
      expect(t.direction, RtpTransceiverDirection.recvonly); // kept, recv-only

      // Idempotent: a second remove is a no-op (no further downgrade).
      pc.removeTrack(sender);
      expect(t.direction, RtpTransceiverDirection.recvonly);
    });

    test('removeTrack on a sendonly transceiver goes inactive', () async {
      final t = pc.addTransceiver('audio', direction: 'sendonly');
      await t.sender!.replaceTrack(_FakeTrack('t1', 'audio'));
      pc.removeTrack(t.sender!);
      expect(t.direction, RtpTransceiverDirection.inactive);
    });

    test('removeTrack ignores a sender not owned by this connection', () {
      final other = PeerConnection(
          configuration: const PeerConnectionConfiguration());
      final foreign = other.addTrack(_FakeTrack('t1', 'audio'));
      expect(() => pc.removeTrack(foreign), returnsNormally);
      expect(foreign.track, isNotNull); // untouched
      other.close();
    });

    test('removeTrack downgrades the m-line direction in the next offer',
        () async {
      final sender = pc.addTrack(_FakeTrack('t1', 'audio'));
      final offer1 = await pc.createOffer();
      expect(offer1.sdp, contains('a=sendrecv'));

      pc.removeTrack(sender);
      final offer2 = await pc.createOffer();
      expect(offer2.sdp, contains('a=recvonly'));
      expect(offer2.sdp, isNot(contains('a=sendrecv')));
    });
  });

  group('RtpSender.getParameters / setParameters', () {
    late PeerConnection pc;
    late RtpSender sender;
    setUp(() {
      pc = PeerConnection(configuration: const PeerConnectionConfiguration());
      sender = pc.addTrack(_FakeTrack('t1', 'audio'));
    });
    tearDown(() => pc.close());

    test('getParameters returns one active encoding with a transactionId', () {
      final p = sender.getParameters();
      expect(p.transactionId, isNotEmpty);
      expect(p.encodings, hasLength(1));
      expect(p.encodings.single.active, isTrue);
      expect(p.encodings.single.maxBitrate, isNull);
      // Each call mints a fresh token.
      expect(sender.getParameters().transactionId, isNot(p.transactionId));
    });

    test('setParameters applies mutable fields, reflected next getParameters',
        () async {
      final p = sender.getParameters();
      p.encodings.single
        ..active = false
        ..maxBitrate = 128000
        ..maxFramerate = 30;
      await sender.setParameters(p);

      final after = sender.getParameters().encodings.single;
      expect(after.active, isFalse);
      expect(after.maxBitrate, 128000);
      expect(after.maxFramerate, 30);
    });

    test('setParameters rejects a stale/mismatched transactionId', () async {
      final p = sender.getParameters();
      sender.getParameters(); // supersedes p's token
      await expectLater(sender.setParameters(p), throwsStateError);
    });

    test('a transactionId is single-use', () async {
      final p = sender.getParameters();
      await sender.setParameters(p); // consumes the token
      await expectLater(sender.setParameters(p), throwsStateError);
    });

    test('setParameters cannot change the number of encodings', () async {
      final p = sender.getParameters();
      final two = RtpSendParameters(
        transactionId: p.transactionId,
        encodings: [RtpEncodingParameters(), RtpEncodingParameters()],
      );
      await expectLater(sender.setParameters(two), throwsStateError);
    });

    test('an inactive encoding drops outgoing RTP', () async {
      // Baseline: an active sender counts the packet (SRTP isn't set up, so the
      // send callback no-ops, but the stat counter still advances).
      sender.sendRtp(Uint8List.fromList([1, 2, 3]));
      expect(sender.packetsSent, 1);

      final p = sender.getParameters();
      p.encodings.single.active = false;
      await sender.setParameters(p);

      sender.sendRtp(Uint8List.fromList([4, 5, 6]));
      expect(sender.packetsSent, 1); // unchanged — dropped before the wire
    });
  });
}
