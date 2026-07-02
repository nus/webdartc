/// Opus audio decoder backend powered by Android MediaCodec.
///
/// Available on Android when the device provides an Opus decoder (probed at
/// registration). Drives [MediaCodecOpusDecoder] — which configures itself with
/// a synthesised OpusHead csd since WebRTC has no container — and adapts it to
/// the W3C-style [AudioDecoderBackend]: Opus packets in, s16 interleaved PCM out.
library;

import '../../media/audio_data.dart';
import '../audio_codec.dart';
import '../mediacodec/mediacodec_audio.dart';

final class MediaCodecOpusDecoderBackend implements AudioDecoderBackend {
  MediaCodecOpusDecoder? _dec;

  int _sampleRate = 48000;
  int _channels = 2;

  void Function(AudioData)? _onOutput;
  void Function(Object)? _onError;

  @override
  set onOutput(void Function(AudioData) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(AudioDecoderConfig config) {
    _sampleRate = config.sampleRate;
    _channels = config.numberOfChannels;
    _dec = MediaCodecOpusDecoder.create(_sampleRate, _channels);
  }

  @override
  void decode(EncodedAudioChunk chunk) {
    final dec = _dec;
    if (dec == null) {
      _onError?.call(StateError('Decoder not configured'));
      return;
    }
    try {
      for (final pcm in dec.decode(chunk.data, chunk.timestamp)) {
        final samplesPerChannel = pcm.data.length ~/ 2 ~/ _channels;
        _onOutput?.call(AudioData(
          format: AudioSampleFormat.s16,
          sampleRate: _sampleRate,
          numberOfChannels: _channels,
          numberOfFrames: samplesPerChannel,
          timestamp: pcm.ptsUs,
          duration: (samplesPerChannel * 1000000) ~/ _sampleRate,
          data: pcm.data,
        ));
      }
    } catch (e) {
      _onError?.call(e);
    }
  }

  @override
  Future<void> flush() async {
    // decode() drains synchronously; nothing is buffered.
  }

  @override
  void reset() => close();

  @override
  void close() {
    _dec?.close();
    _dec = null;
  }
}
