/// Opus audio encoder backend powered by libopus (RFC 6716).
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/audio_data.dart';
import '../audio_codec.dart';
import '_libopus.dart' as op;
import 'opus_pcm_framer.dart';

/// Maximum Opus packet size per RFC 6716 §3.
const int _maxOpusPacketBytes = 1275;

/// 20 ms per frame — WebRTC `ptime` default.
const int _frameDurationUs = 20000;

/// Default bitrate for stereo VoIP when caller provides none.
const int _defaultBitrate = 32000;

final class OpusEncoderBackend implements AudioEncoderBackend {
  ffi.Pointer<op.OpusEncoder>? _encoder;
  AudioDecoderConfig? _decoderConfig;

  void Function(EncodedAudioChunk, EncodedAudioChunkMetadata?)? _onOutput;
  void Function(Object)? _onError;

  int _sampleRate = 48000;
  int _channels = 2;
  int _samplesPerFrame = 960;
  int _samplesPerFrameAllChannels = 1920;

  // Persistent native scratch buffers (allocated in configure, freed in close).
  ffi.Pointer<ffi.Int16> _pcmScratch = ffi.nullptr;
  ffi.Pointer<ffi.UnsignedChar> _outScratch = ffi.nullptr;

  // Slices arbitrary PCM chunks into 20 ms frames with a continuous PTS.
  OpusPcmFramer? _framer;

  @override
  set onOutput(void Function(EncodedAudioChunk, EncodedAudioChunkMetadata?) cb) =>
      _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(AudioEncoderConfig config) {
    _sampleRate = config.sampleRate;
    _channels = config.numberOfChannels;
    _samplesPerFrame = (_sampleRate * _frameDurationUs) ~/ 1000000;
    _samplesPerFrameAllChannels = _samplesPerFrame * _channels;

    final errPtr = pkgffi.calloc<ffi.Int>();
    final enc = op.opusEncoderCreate(
      _sampleRate,
      _channels,
      op.opusApplicationVoip,
      errPtr,
    );
    final err = errPtr.value;
    pkgffi.calloc.free(errPtr);
    if (err != op.opusOk || enc == ffi.nullptr) {
      throw StateError('opus_encoder_create failed: $err');
    }

    final bitrate = config.bitrate ?? _defaultBitrate;
    final ctlRes = op.opusEncoderCtlInt(enc, op.opusSetBitrateRequest, bitrate);
    if (ctlRes != op.opusOk) {
      op.opusEncoderDestroy(enc);
      throw StateError('OPUS_SET_BITRATE failed: $ctlRes');
    }

    _encoder = enc;
    _pcmScratch = pkgffi.calloc<ffi.Int16>(_samplesPerFrameAllChannels);
    _outScratch = pkgffi.calloc<ffi.UnsignedChar>(_maxOpusPacketBytes);
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
    final encoder = _encoder;
    if (encoder == null) {
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

    final sampleCount = data.numberOfFrames * data.numberOfChannels;
    if (data.data.offsetInBytes.isOdd) {
      _onError?.call(StateError(
          'Opus encoder requires 16-bit aligned PCM buffer'));
      return;
    }
    final view = Int16List.view(
        data.data.buffer, data.data.offsetInBytes, sampleCount);

    _framer!.add(view, data.timestamp, _emitFrame);
  }

  void _emitFrame(Int16List src, int srcOffset, int ts) {
    final pcmList = _pcmScratch
        .cast<ffi.Int16>()
        .asTypedList(_samplesPerFrameAllChannels);
    pcmList.setRange(0, _samplesPerFrameAllChannels, src, srcOffset);

    final encoded = op.opusEncode(
      _encoder!,
      _pcmScratch,
      _samplesPerFrame,
      _outScratch,
      _maxOpusPacketBytes,
    );
    if (encoded < 0) {
      _onError?.call(StateError('opus_encode failed: $encoded'));
      return;
    }

    final outView = _outScratch.cast<ffi.Uint8>().asTypedList(encoded);
    final bytes = Uint8List(encoded)..setRange(0, encoded, outView);
    _onOutput?.call(
      EncodedAudioChunk(
        type: EncodedAudioChunkType.key,
        timestamp: ts,
        duration: _frameDurationUs,
        data: bytes,
      ),
      EncodedAudioChunkMetadata(decoderConfig: _decoderConfig),
    );
  }

  @override
  Future<void> flush() async {
    // libopus has no buffered output; sub-frame remainder is dropped.
    _framer?.reset();
  }

  @override
  void reset() => close();

  @override
  void close() {
    final enc = _encoder;
    if (enc != null) {
      op.opusEncoderDestroy(enc);
      _encoder = null;
    }
    if (_pcmScratch != ffi.nullptr) {
      pkgffi.calloc.free(_pcmScratch);
      _pcmScratch = ffi.nullptr;
    }
    if (_outScratch != ffi.nullptr) {
      pkgffi.calloc.free(_outScratch);
      _outScratch = ffi.nullptr;
    }
    _framer = null;
  }
}
