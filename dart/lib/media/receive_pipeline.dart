/// Decode pipeline for one remote RTP media stream: jitter buffer →
/// depacketize → decode → [ReceiverVideoTrack] / [ReceiverAudioTrack].
///
/// Separated from `RtpReceiver` so it can be unit-tested in isolation (feed
/// synthetic RTP, assert decoded frames on the track) without standing up a
/// full PeerConnection. The pipeline is built lazily: [ReceivePipeline
/// .tryCreate] makes the track eagerly (so a renderer can attach), and the
/// decoder/depacketizer/jitter buffer are constructed on the first listener.
library;

import '../codec/audio_codec.dart';
import '../codec/codec_registry.dart';
import '../codec/video_codec.dart';
import '../crypto/csprng.dart';
import '../rtp/jitter_buffer.dart';
import '../rtp/packetizer.dart';
import '../rtp/parser.dart';
import 'receiver_track.dart';

/// Receive-side decode pipeline for a single SSRC / track.
final class ReceivePipeline {
  final String kind; // 'audio' | 'video'
  final bool _isVideo;
  final String codecKey; // CodecRegistry key, e.g. 'vp8' / 'opus'
  final int clockRate;
  final int channels;
  final void Function()? requestKeyframe; // sends a PLI
  final void Function(Object error)? onError;

  /// The decoded-media track fed by this pipeline.
  final ReceiverTrack<Object> track;

  JitterBuffer? _jitter;
  VideoPayloadDepacketizer? _videoDepack;
  AudioPayloadDepacketizer? _audioDepack;
  VideoDecoderBackend? _videoDecoder;
  AudioDecoderBackend? _audioDecoder;
  bool _active = false;
  bool _decoderConfigured = false;

  // Keyframe gating + PLI retransmit (video only).
  bool _firstKeyframeDecoded = false;
  int _lastPliUs = 0;
  int _pliRetries = 0;
  static const _pliRetryIntervalUs = 1000000; // 1 s
  static const _pliMaxRetries = 5;

  ReceivePipeline._({
    required this.kind,
    required this.codecKey,
    required this.clockRate,
    required this.channels,
    required this.track,
    this.requestKeyframe,
    this.onError,
  }) : _isVideo = kind == 'video';

  /// Build a pipeline + track for [codecKey] if the codec is fully supported
  /// (a decoder backend is registered *and* an RTP depacketizer exists).
  /// Returns null otherwise — the caller should fall back to raw RTP access.
  /// Probing registration does not instantiate a backend, so no native library
  /// is loaded here.
  static ReceivePipeline? tryCreate({
    required String kind,
    required String codecKey,
    required int clockRate,
    required int channels,
    void Function()? requestKeyframe,
    void Function(Object error)? onError,
  }) {
    final ReceiverTrack<Object> track;
    if (kind == 'video') {
      if (!CodecRegistry.hasVideoDecoder(codecKey)) return null;
      if (videoDepacketizerFor(codecKey) == null) return null;
      track = ReceiverVideoTrack(id: Csprng.randomHex(16));
    } else if (kind == 'audio') {
      if (!CodecRegistry.hasAudioDecoder(codecKey)) return null;
      if (audioDepacketizerFor(codecKey) == null) return null;
      track = ReceiverAudioTrack(id: Csprng.randomHex(16));
    } else {
      return null;
    }
    final p = ReceivePipeline._(
      kind: kind,
      codecKey: codecKey,
      clockRate: clockRate,
      channels: channels,
      track: track,
      requestKeyframe: requestKeyframe,
      onError: onError,
    );
    track
      ..onActivate = p.activate
      ..onDeactivate = p._maybeDeactivate;
    return p;
  }

  /// Whether the decode pipeline is currently running.
  bool get isActive => _active;

  /// Build the decode pipeline (instantiating the decoder loads its native
  /// library). Any failure leaves the pipeline inactive — the track simply
  /// emits nothing while raw RTP access keeps working upstream.
  void activate() {
    if (_active) return;
    try {
      _jitter = JitterBuffer();
      if (_isVideo) {
        _videoDepack = videoDepacketizerFor(codecKey);
        final dec = CodecRegistry.createVideoDecoder(codecKey);
        if (dec == null || _videoDepack == null) return;
        dec.onOutput = (frame) {
          _firstKeyframeDecoded = true;
          (track as ReceiverVideoTrack).deliverFrame(frame);
        };
        dec.onError = _report;
        _videoDecoder = dec;
      } else {
        _audioDepack = audioDepacketizerFor(codecKey);
        final dec = CodecRegistry.createAudioDecoder(codecKey);
        if (dec == null || _audioDepack == null) return;
        dec.onOutput = (data) => (track as ReceiverAudioTrack).deliverAudio(data);
        dec.onError = _report;
        // Audio has no keyframe concept — configure immediately.
        dec.configure(AudioDecoderConfig(
          codec: codecKey,
          sampleRate: clockRate,
          numberOfChannels: channels,
        ));
        _decoderConfigured = true;
        _audioDecoder = dec;
      }
      _active = true;
    } catch (e) {
      _report(e);
      _teardownDecoders();
    }
  }

  void _maybeDeactivate() {
    if (track.hasListener) return;
    _teardownDecoders();
    _active = false;
    _decoderConfigured = false;
    _firstKeyframeDecoded = false;
    _jitter = null;
  }

  /// Feed an arriving RTP [packet] (received at [arrivalUs] on the same clock
  /// passed to [tick]). No-op until the pipeline is active.
  void add(RtpPacket packet, int arrivalUs) {
    if (_active) _jitter?.add(packet, arrivalUs);
  }

  /// Periodic pump: release jitter-buffered packets, depacketize, decode, and
  /// retransmit PLI as needed.
  void tick(int nowUs) {
    if (!_active) return;
    final packets = _jitter?.drain(nowUs) ?? const [];
    if (_isVideo) {
      for (final p in packets) {
        _decodeVideoPacket(p);
      }
      _maybeRetransmitPli(nowUs);
    } else {
      for (final p in packets) {
        _decodeAudioPacket(p);
      }
    }
  }

  void _decodeVideoPacket(RtpPacket p) {
    final chunk = _videoDepack?.depacketize(
      p.payload,
      marker: p.marker,
      timestamp: p.timestamp,
    );
    if (chunk == null) return;
    // Keyframe gate: wait for the first keyframe so the decoder has a
    // reference frame (VP8) / SPS+PPS (H.264).
    if (!_decoderConfigured) {
      if (chunk.type != EncodedVideoChunkType.key) return;
      _videoDecoder?.configure(VideoDecoderConfig(codec: codecKey));
      _decoderConfigured = true;
    }
    _videoDecoder?.decode(chunk);
  }

  void _decodeAudioPacket(RtpPacket p) {
    final chunk = _audioDepack?.depacketize(p.payload, timestamp: p.timestamp);
    if (chunk == null) return;
    _audioDecoder?.decode(chunk);
  }

  /// Re-request a keyframe via PLI if the video stream hasn't produced one yet
  /// — covers a lost initial PLI or a slow/joining sender.
  void _maybeRetransmitPli(int nowUs) {
    // Only reached on the video path (see [tick]).
    if (_firstKeyframeDecoded) return;
    if (_pliRetries >= _pliMaxRetries) return;
    // First tick after activation establishes the baseline — the initial PLI
    // is sent on track creation, so wait one interval before retransmitting.
    if (_lastPliUs == 0) {
      _lastPliUs = nowUs;
      return;
    }
    if (nowUs - _lastPliUs < _pliRetryIntervalUs) return;
    _lastPliUs = nowUs;
    _pliRetries++;
    requestKeyframe?.call();
  }

  void _teardownDecoders() {
    _videoDecoder?.close();
    _audioDecoder?.close();
    _videoDecoder = null;
    _audioDecoder = null;
  }

  void _report(Object e) => onError?.call(e);

  /// Release the pipeline and stop the track.
  void close() {
    _teardownDecoders();
    track.stop();
  }
}
