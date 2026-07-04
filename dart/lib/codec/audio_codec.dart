/// W3C WebCodecs — AudioEncoder / AudioDecoder interfaces.
/// https://www.w3.org/TR/webcodecs/#audioencoder-interface
/// https://www.w3.org/TR/webcodecs/#audiodecoder-interface
library;

import 'dart:typed_data';

import '../media/audio_data.dart';
import 'codec_frontend.dart';
import 'codec_registry.dart';

// ── Codec identifiers ───────────────────────────────────────────────────────

/// Canonical WebCodecs identifiers for the built-in audio backends.
///
/// These are the keys used by [CodecRegistry] and the `codec` field of
/// [AudioEncoderConfig] / [AudioDecoderConfig]. This is a separate namespace
/// from the IANA RTP name advertised in SDP (see `MediaEngine`); for Opus the
/// two spellings happen to coincide, but they are not the same identifier.
abstract final class AudioCodecName {
  AudioCodecName._();

  static const String opus = 'opus';
}

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

  final CodecFrontendCore<AudioEncoderBackend> _core = CodecFrontendCore('Encoder');

  AudioEncoder({
    required void Function(EncodedAudioChunk, EncodedAudioChunkMetadata?) output,
    required void Function(Object) error,
  })  : _output = output,
        _error = error;

  CodecState get state => _core.state;

  void configure(AudioEncoderConfig config) => _core.configure(
        config.codec,
        () => CodecRegistry.createAudioEncoder(config.codec),
        (backend) => backend
          ..onOutput = _output
          ..onError = _error
          ..configure(config),
      );

  void encode(AudioData data) => _core.submit((backend) => backend.encode(data));

  Future<void> flush() => _core.flush();

  void reset() => _core.reset();

  void close() => _core.close();

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

  final CodecFrontendCore<AudioDecoderBackend> _core = CodecFrontendCore('Decoder');

  AudioDecoder({
    required void Function(AudioData) output,
    required void Function(Object) error,
  })  : _output = output,
        _error = error;

  CodecState get state => _core.state;

  void configure(AudioDecoderConfig config) => _core.configure(
        config.codec,
        () => CodecRegistry.createAudioDecoder(config.codec),
        (backend) => backend
          ..onOutput = _output
          ..onError = _error
          ..configure(config),
      );

  void decode(EncodedAudioChunk chunk) => _core.submit((backend) => backend.decode(chunk));

  Future<void> flush() => _core.flush();

  void reset() => _core.reset();

  void close() => _core.close();

  static Future<AudioDecoderSupport> isConfigSupported(AudioDecoderConfig config) async {
    return AudioDecoderSupport(
      supported: CodecRegistry.hasAudioDecoder(config.codec),
      config: config,
    );
  }
}

// ── Backend interfaces (for codec implementors) ─────────────────────────────

abstract interface class AudioEncoderBackend implements CodecBackend {
  void configure(AudioEncoderConfig config);
  void encode(AudioData data);
  set onOutput(void Function(EncodedAudioChunk, EncodedAudioChunkMetadata?) cb);
  set onError(void Function(Object) cb);
}

abstract interface class AudioDecoderBackend implements CodecBackend {
  void configure(AudioDecoderConfig config);
  void decode(EncodedAudioChunk chunk);
  set onOutput(void Function(AudioData) cb);
  set onError(void Function(Object) cb);
}
