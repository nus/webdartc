/// W3C WebCodecs — AudioEncoder / AudioDecoder interfaces.
/// https://www.w3.org/TR/webcodecs/#audioencoder-interface
/// https://www.w3.org/TR/webcodecs/#audiodecoder-interface
library;

import 'dart:typed_data';

import '../media/audio_data.dart';
import 'codec_registry.dart';
import 'video_codec.dart' show CodecState;

// ── Encoded data ────────────────────────────────────────────────────────────

enum EncodedAudioChunkType { key, delta }

/// An encoded audio frame.
final class EncodedAudioChunk {
  final EncodedAudioChunkType type;
  final int timestamp;
  final int? duration;
  final Uint8List data;

  const EncodedAudioChunk({
    required this.type,
    required this.timestamp,
    this.duration,
    required this.data,
  });
}

/// Metadata emitted alongside an encoded audio chunk.
final class EncodedAudioChunkMetadata {
  final AudioDecoderConfig? decoderConfig;
  const EncodedAudioChunkMetadata({this.decoderConfig});
}

// ── Config types ────────────────────────────────────────────────────────────

final class AudioEncoderConfig {
  final String codec;
  final int sampleRate;
  final int numberOfChannels;
  final int? bitrate;

  const AudioEncoderConfig({
    required this.codec,
    required this.sampleRate,
    required this.numberOfChannels,
    this.bitrate,
  });
}

final class AudioDecoderConfig {
  final String codec;
  final int sampleRate;
  final int numberOfChannels;
  final Uint8List? description;

  const AudioDecoderConfig({
    required this.codec,
    required this.sampleRate,
    required this.numberOfChannels,
    this.description,
  });
}

final class AudioEncoderSupport {
  final bool supported;
  final AudioEncoderConfig config;
  const AudioEncoderSupport({required this.supported, required this.config});
}

final class AudioDecoderSupport {
  final bool supported;
  final AudioDecoderConfig config;
  const AudioDecoderSupport({required this.supported, required this.config});
}

// ── AudioEncoder (W3C public API) ───────────────────────────────────────────

/// W3C AudioEncoder — output callback receives encoded chunks.
final class AudioEncoder {
  final void Function(EncodedAudioChunk chunk, EncodedAudioChunkMetadata? metadata) _output;
  final void Function(Object error) _error;

  AudioEncoderBackend? _backend;
  CodecState _state = CodecState.unconfigured;

  AudioEncoder({
    required void Function(EncodedAudioChunk, EncodedAudioChunkMetadata?) output,
    required void Function(Object) error,
  })  : _output = output,
        _error = error;

  CodecState get state => _state;

  void configure(AudioEncoderConfig config) {
    if (_state == CodecState.closed) throw StateError('Encoder is closed');
    _backend = CodecRegistry.createAudioEncoder(config.codec);
    if (_backend == null) throw UnsupportedError('No backend for codec: ${config.codec}');
    _backend!.onOutput = _output;
    _backend!.onError = _error;
    _backend!.configure(config);
    _state = CodecState.configured;
  }

  void encode(AudioData data) {
    if (_state != CodecState.configured) throw StateError('Encoder not configured');
    _backend!.encode(data);
  }

  Future<void> flush() async {
    if (_state != CodecState.configured) return;
    await _backend!.flush();
  }

  void reset() {
    if (_state == CodecState.closed) return;
    _backend?.reset();
    _state = CodecState.unconfigured;
  }

  void close() {
    if (_state == CodecState.closed) return;
    _backend?.close();
    _state = CodecState.closed;
  }

  static Future<AudioEncoderSupport> isConfigSupported(AudioEncoderConfig config) async {
    return AudioEncoderSupport(
      supported: CodecRegistry.hasAudioEncoder(config.codec),
      config: config,
    );
  }
}

// ── AudioDecoder (W3C public API) ───────────────────────────────────────────

/// W3C AudioDecoder — output callback receives decoded audio.
final class AudioDecoder {
  final void Function(AudioData data) _output;
  final void Function(Object error) _error;

  AudioDecoderBackend? _backend;
  CodecState _state = CodecState.unconfigured;

  AudioDecoder({
    required void Function(AudioData) output,
    required void Function(Object) error,
  })  : _output = output,
        _error = error;

  CodecState get state => _state;

  void configure(AudioDecoderConfig config) {
    if (_state == CodecState.closed) throw StateError('Decoder is closed');
    _backend = CodecRegistry.createAudioDecoder(config.codec);
    if (_backend == null) throw UnsupportedError('No backend for codec: ${config.codec}');
    _backend!.onOutput = _output;
    _backend!.onError = _error;
    _backend!.configure(config);
    _state = CodecState.configured;
  }

  void decode(EncodedAudioChunk chunk) {
    if (_state != CodecState.configured) throw StateError('Decoder not configured');
    _backend!.decode(chunk);
  }

  Future<void> flush() async {
    if (_state != CodecState.configured) return;
    await _backend!.flush();
  }

  void reset() {
    if (_state == CodecState.closed) return;
    _backend?.reset();
    _state = CodecState.unconfigured;
  }

  void close() {
    if (_state == CodecState.closed) return;
    _backend?.close();
    _state = CodecState.closed;
  }

  static Future<AudioDecoderSupport> isConfigSupported(AudioDecoderConfig config) async {
    return AudioDecoderSupport(
      supported: CodecRegistry.hasAudioDecoder(config.codec),
      config: config,
    );
  }
}

// ── Backend interfaces (for codec implementors) ─────────────────────────────

abstract interface class AudioEncoderBackend {
  void configure(AudioEncoderConfig config);
  void encode(AudioData data);
  Future<void> flush();
  void reset();
  void close();
  set onOutput(void Function(EncodedAudioChunk, EncodedAudioChunkMetadata?) cb);
  set onError(void Function(Object) cb);
}

abstract interface class AudioDecoderBackend {
  void configure(AudioDecoderConfig config);
  void decode(EncodedAudioChunk chunk);
  Future<void> flush();
  void reset();
  void close();
  set onOutput(void Function(AudioData) cb);
  set onError(void Function(Object) cb);
}
