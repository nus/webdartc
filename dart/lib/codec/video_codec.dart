/// W3C WebCodecs — VideoEncoder / VideoDecoder interfaces.
/// https://www.w3.org/TR/webcodecs/#videoencoder-interface
/// https://www.w3.org/TR/webcodecs/#videodecoder-interface
library;

import 'dart:typed_data';

import '../media/video_frame.dart';
import 'codec_registry.dart';

// ── Encoded data ────────────────────────────────────────────────────────────

enum EncodedVideoChunkType { key, delta }

/// An encoded video frame.
final class EncodedVideoChunk {
  final EncodedVideoChunkType type;
  final int timestamp;
  final int? duration;
  final Uint8List data;

  const EncodedVideoChunk({
    required this.type,
    required this.timestamp,
    this.duration,
    required this.data,
  });
}

/// Metadata emitted alongside an encoded video chunk.
final class EncodedVideoChunkMetadata {
  final VideoDecoderConfig? decoderConfig;
  const EncodedVideoChunkMetadata({this.decoderConfig});
}

// ── Config types ────────────────────────────────────────────────────────────

final class VideoEncoderConfig {
  final String codec;
  final int width;
  final int height;
  final int? bitrate;
  final double? framerate;
  final String? latencyMode; // 'quality' | 'realtime'

  const VideoEncoderConfig({
    required this.codec,
    required this.width,
    required this.height,
    this.bitrate,
    this.framerate,
    this.latencyMode,
  });
}

final class VideoDecoderConfig {
  final String codec;
  final int? codedWidth;
  final int? codedHeight;
  final Uint8List? description;

  const VideoDecoderConfig({
    required this.codec,
    this.codedWidth,
    this.codedHeight,
    this.description,
  });
}

final class VideoEncoderEncodeOptions {
  final bool keyFrame;
  const VideoEncoderEncodeOptions({this.keyFrame = false});
}

final class VideoEncoderSupport {
  final bool supported;
  final VideoEncoderConfig config;
  const VideoEncoderSupport({required this.supported, required this.config});
}

final class VideoDecoderSupport {
  final bool supported;
  final VideoDecoderConfig config;
  const VideoDecoderSupport({required this.supported, required this.config});
}

// ── Codec state ─────────────────────────────────────────────────────────────

enum CodecState { unconfigured, configured, closed }

// ── VideoEncoder (W3C public API) ───────────────────────────────────────────

/// W3C VideoEncoder — output callback receives encoded chunks.
final class VideoEncoder {
  final void Function(EncodedVideoChunk chunk, EncodedVideoChunkMetadata? metadata) _output;
  final void Function(Object error) _error;

  VideoEncoderBackend? _backend;
  CodecState _state = CodecState.unconfigured;

  VideoEncoder({
    required void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?) output,
    required void Function(Object) error,
  })  : _output = output,
        _error = error;

  CodecState get state => _state;

  void configure(VideoEncoderConfig config) {
    if (_state == CodecState.closed) throw StateError('Encoder is closed');
    _backend = CodecRegistry.createVideoEncoder(config.codec);
    if (_backend == null) throw UnsupportedError('No backend for codec: ${config.codec}');
    _backend!.onOutput = _output;
    _backend!.onError = _error;
    _backend!.configure(config);
    _state = CodecState.configured;
  }

  void encode(VideoFrame frame, [VideoEncoderEncodeOptions? options]) {
    if (_state != CodecState.configured) throw StateError('Encoder not configured');
    _backend!.encode(frame, keyFrame: options?.keyFrame ?? false);
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

  static Future<VideoEncoderSupport> isConfigSupported(VideoEncoderConfig config) async {
    return VideoEncoderSupport(
      supported: CodecRegistry.hasVideoEncoder(config.codec),
      config: config,
    );
  }
}

// ── VideoDecoder (W3C public API) ───────────────────────────────────────────

/// W3C VideoDecoder — output callback receives decoded frames.
final class VideoDecoder {
  final void Function(VideoFrame frame) _output;
  final void Function(Object error) _error;

  VideoDecoderBackend? _backend;
  CodecState _state = CodecState.unconfigured;

  VideoDecoder({
    required void Function(VideoFrame) output,
    required void Function(Object) error,
  })  : _output = output,
        _error = error;

  CodecState get state => _state;

  void configure(VideoDecoderConfig config) {
    if (_state == CodecState.closed) throw StateError('Decoder is closed');
    _backend = CodecRegistry.createVideoDecoder(config.codec);
    if (_backend == null) throw UnsupportedError('No backend for codec: ${config.codec}');
    _backend!.onOutput = _output;
    _backend!.onError = _error;
    _backend!.configure(config);
    _state = CodecState.configured;
  }

  void decode(EncodedVideoChunk chunk) {
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

  static Future<VideoDecoderSupport> isConfigSupported(VideoDecoderConfig config) async {
    return VideoDecoderSupport(
      supported: CodecRegistry.hasVideoDecoder(config.codec),
      config: config,
    );
  }
}

// ── Backend interfaces (for codec implementors) ─────────────────────────────

/// Codec implementors provide this interface.
/// VideoEncoder delegates to it internally.
abstract interface class VideoEncoderBackend {
  void configure(VideoEncoderConfig config);
  void encode(VideoFrame frame, {bool keyFrame = false});
  Future<void> flush();
  void reset();
  void close();
  set onOutput(void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?) cb);
  set onError(void Function(Object) cb);
}

/// Codec implementors provide this interface.
/// VideoDecoder delegates to it internally.
abstract interface class VideoDecoderBackend {
  void configure(VideoDecoderConfig config);
  void decode(EncodedVideoChunk chunk);
  Future<void> flush();
  void reset();
  void close();
  set onOutput(void Function(VideoFrame) cb);
  set onError(void Function(Object) cb);
}
