/// Opus audio encoder backend powered by Android MediaCodec.
///
/// Available on Android when the device provides an Opus encoder (probed at
/// registration). Drives [MediaCodecOpusEncoder] and adapts it to the W3C-style
/// [AudioEncoderBackend]. Input PCM is sliced into 20 ms frames by the shared
/// [OpusPcmFramer] (same as the libopus backend) and fed one frame at a time;
/// output PTS travels with each Opus packet (MediaCodec pipeline latency).
library;

import 'dart:typed_data';

import '../../media/audio_data.dart';
import '../audio_codec.dart';
import '../mediacodec/mediacodec_audio.dart';
import 'opus_pcm_framer.dart';

/// 20 ms per frame — WebRTC `ptime` default.
const int _frameDurationUs = 20000;
const int _defaultBitrate = 32000;

final class MediaCodecOpusEncoderBackend implements AudioEncoderBackend {
  MediaCodecOpusEncoder? _enc;
  OpusPcmFramer? _framer;
  AudioDecoderConfig? _decoderConfig;

  int _sampleRate = 48000;
  int _channels = 2;
  int _samplesPerFrameAllChannels = 1920;

  void Function(EncodedAudioChunk, EncodedAudioChunkMetadata?)? _onOutput;
  void Function(Object)? _onError;

  @override
  set onOutput(void Function(EncodedAudioChunk, EncodedAudioChunkMetadata?) cb) =>
      _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(AudioEncoderConfig config) {
    _sampleRate = config.sampleRate;
    _channels = config.numberOfChannels;
    final samplesPerFrame = (_sampleRate * _frameDurationUs) ~/ 1000000;
    _samplesPerFrameAllChannels = samplesPerFrame * _channels;

    _enc = MediaCodecOpusEncoder.create(
        _sampleRate, _channels, config.bitrate ?? _defaultBitrate);
    _framer = OpusPcmFramer(
      samplesPerFrameAllChannels: _samplesPerFrameAllChannels,
      frameDurationUs: _frameDurationUs,
    );
    _decoderConfig = AudioDecoderConfig(
      codec: AudioCodecName.opus,
      sampleRate: _sampleRate,
      numberOfChannels: _channels,
    );
  }

  @override
  void encode(AudioData data) {
    final framer = _framer;
    if (framer == null) {
      _onError?.call(StateError('Encoder not configured'));
      return;
    }
    if (data.format != AudioSampleFormat.s16) {
      _onError?.call(StateError('Opus encoder requires s16 PCM input'));
      return;
    }
    if (data.sampleRate != _sampleRate ||
        data.numberOfChannels != _channels) {
      _onError?.call(StateError(
          'Format mismatch: configured ${_sampleRate}Hz/${_channels}ch, '
          'got ${data.sampleRate}Hz/${data.numberOfChannels}ch'));
      return;
    }
    if (data.data.offsetInBytes.isOdd) {
      _onError?.call(
          StateError('Opus encoder requires 16-bit aligned PCM buffer'));
      return;
    }
    final view = Int16List.view(data.data.buffer, data.data.offsetInBytes,
        data.numberOfFrames * data.numberOfChannels);
    framer.add(view, data.timestamp, _emitFrame);
  }

  void _emitFrame(Int16List src, int srcOffset, int ptsUs) {
    final frame =
        Int16List.sublistView(src, srcOffset, srcOffset + _samplesPerFrameAllChannels);
    final bytes =
        frame.buffer.asUint8List(frame.offsetInBytes, frame.lengthInBytes);
    try {
      for (final pkt in _enc!.encode(bytes, ptsUs)) {
        _onOutput?.call(
          EncodedAudioChunk(
            type: EncodedAudioChunkType.key,
            timestamp: pkt.ptsUs,
            duration: _frameDurationUs,
            data: pkt.data,
          ),
          EncodedAudioChunkMetadata(decoderConfig: _decoderConfig),
        );
      }
    } catch (e) {
      _onError?.call(e);
    }
  }

  @override
  Future<void> flush() async {
    _framer?.reset();
  }

  @override
  void reset() => close();

  @override
  void close() {
    _enc?.close();
    _enc = null;
    _framer = null;
  }
}
