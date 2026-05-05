/// Opus audio decoder backend powered by libopus (RFC 6716).
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/audio_data.dart';
import '../audio_codec.dart';
import '_libopus.dart';
import 'opus_bindings.g.dart' as op;

/// Per RFC 6716 §2.1.4 the longest Opus frame is 120 ms; at 48 kHz that's
/// 5760 samples per channel — used as the per-call decode buffer ceiling.
const int _maxSamplesPerChannelPerFrame = 5760;

final class OpusDecoderBackend implements AudioDecoderBackend {
  ffi.Pointer<op.OpusDecoder>? _decoder;

  void Function(AudioData)? _onOutput;
  void Function(Object)? _onError;

  int _sampleRate = 48000;
  int _channels = 2;

  // Persistent output scratch (allocated in configure, freed in close).
  ffi.Pointer<op.opus_int16> _outScratch = ffi.nullptr;

  @override
  set onOutput(void Function(AudioData) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(AudioDecoderConfig config) {
    _sampleRate = config.sampleRate;
    _channels = config.numberOfChannels;

    final errPtr = pkgffi.calloc<ffi.Int>();
    final dec = libopus.opus_decoder_create(_sampleRate, _channels, errPtr);
    final err = errPtr.value;
    pkgffi.calloc.free(errPtr);
    if (err != op.OPUS_OK || dec == ffi.nullptr) {
      throw StateError('opus_decoder_create failed: $err');
    }
    _decoder = dec;
    _outScratch = pkgffi.calloc<op.opus_int16>(
        _maxSamplesPerChannelPerFrame * _channels);
  }

  @override
  void decode(EncodedAudioChunk chunk) {
    final decoder = _decoder;
    if (decoder == null) {
      _onError?.call(StateError('Decoder not configured'));
      return;
    }

    final inPtr = pkgffi.calloc<ffi.UnsignedChar>(chunk.data.length);
    try {
      inPtr.cast<ffi.Uint8>().asTypedList(chunk.data.length)
          .setAll(0, chunk.data);

      final samplesPerChannel = libopus.opus_decode(
        decoder,
        inPtr,
        chunk.data.length,
        _outScratch,
        _maxSamplesPerChannelPerFrame,
        0, // decode_fec
      );
      if (samplesPerChannel < 0) {
        _onError?.call(StateError('opus_decode failed: $samplesPerChannel'));
        return;
      }

      final totalSamples = samplesPerChannel * _channels;
      final pcmBytes = Uint8List(totalSamples * 2);
      Int16List.view(pcmBytes.buffer).setRange(
        0,
        totalSamples,
        _outScratch.cast<ffi.Int16>().asTypedList(totalSamples),
      );

      _onOutput?.call(AudioData(
        format: AudioSampleFormat.s16,
        sampleRate: _sampleRate,
        numberOfChannels: _channels,
        numberOfFrames: samplesPerChannel,
        timestamp: chunk.timestamp,
        duration: (samplesPerChannel * 1000000) ~/ _sampleRate,
        data: pcmBytes,
      ));
    } finally {
      pkgffi.calloc.free(inPtr);
    }
  }

  @override
  Future<void> flush() async {
    // libopus has no buffered output; nothing to flush.
  }

  @override
  void reset() => close();

  @override
  void close() {
    final dec = _decoder;
    if (dec != null) {
      libopus.opus_decoder_destroy(dec);
      _decoder = null;
    }
    if (_outScratch != ffi.nullptr) {
      pkgffi.calloc.free(_outScratch);
      _outScratch = ffi.nullptr;
    }
  }
}
