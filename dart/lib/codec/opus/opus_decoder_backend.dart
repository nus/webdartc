/// Opus audio decoder backend powered by libopus (RFC 6716).
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/audio_data.dart';
import '../audio_codec.dart';
import '_libopus.dart' as op;

/// Per RFC 6716 §2.1.4 the longest Opus frame is 120 ms; at 48 kHz that's
/// 5760 samples per channel — used as the per-call decode buffer ceiling.
const int _maxSamplesPerChannelPerFrame = 5760;

/// Per RFC 6716 §3 an Opus packet is at most 1275 bytes, but in practice
/// can be padded with the framing extensions up to a few KB. 4 KiB
/// covers anything realistic and keeps the per-decoder allocation tiny.
const int _maxEncodedPacketBytes = 4096;

final class OpusDecoderBackend implements AudioDecoderBackend {
  ffi.Pointer<op.OpusDecoder>? _decoder;

  void Function(AudioData)? _onOutput;
  void Function(Object)? _onError;

  int _sampleRate = 48000;
  int _channels = 2;

  // Persistent native scratch buffers (allocated in configure, freed in
  // close). Reusing them avoids a calloc/free per RTP packet on the audio
  // decode hot path.
  ffi.Pointer<ffi.Int16> _outScratch = ffi.nullptr;
  ffi.Pointer<ffi.UnsignedChar> _inScratch = ffi.nullptr;

  @override
  set onOutput(void Function(AudioData) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(AudioDecoderConfig config) {
    _sampleRate = config.sampleRate;
    _channels = config.numberOfChannels;

    final errPtr = pkgffi.calloc<ffi.Int>();
    final dec = op.opusDecoderCreate(_sampleRate, _channels, errPtr);
    final err = errPtr.value;
    pkgffi.calloc.free(errPtr);
    if (err != op.opusOk || dec == ffi.nullptr) {
      throw StateError('opus_decoder_create failed: $err');
    }
    _decoder = dec;
    _outScratch = pkgffi.calloc<ffi.Int16>(
        _maxSamplesPerChannelPerFrame * _channels);
    _inScratch = pkgffi.calloc<ffi.UnsignedChar>(_maxEncodedPacketBytes);
  }

  @override
  void decode(EncodedAudioChunk chunk) {
    final decoder = _decoder;
    if (decoder == null) {
      _onError?.call(StateError('Decoder not configured'));
      return;
    }
    if (chunk.data.length > _maxEncodedPacketBytes) {
      _onError?.call(StateError(
          'Opus packet too large: ${chunk.data.length} > $_maxEncodedPacketBytes'));
      return;
    }
    _inScratch.cast<ffi.Uint8>().asTypedList(chunk.data.length)
        .setAll(0, chunk.data);

    final samplesPerChannel = op.opusDecode(
      decoder,
      _inScratch,
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
      op.opusDecoderDestroy(dec);
      _decoder = null;
    }
    if (_outScratch != ffi.nullptr) {
      pkgffi.calloc.free(_outScratch);
      _outScratch = ffi.nullptr;
    }
    if (_inScratch != ffi.nullptr) {
      pkgffi.calloc.free(_inScratch);
      _inScratch = ffi.nullptr;
    }
  }
}
