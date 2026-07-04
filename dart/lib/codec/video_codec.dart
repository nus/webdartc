/// W3C WebCodecs — VideoEncoder / VideoDecoder interfaces.
/// https://www.w3.org/TR/webcodecs/#videoencoder-interface
/// https://www.w3.org/TR/webcodecs/#videodecoder-interface
library;

import 'dart:typed_data';

import '../media/video_frame.dart';
import 'codec_frontend.dart';
import 'codec_registry.dart';

export 'codec_frontend.dart' show CodecState;

// ── Codec identifiers ───────────────────────────────────────────────────────

/// Canonical WebCodecs identifiers for the built-in video backends.
///
/// These are the keys used by [CodecRegistry] and the `codec` field of
/// [VideoEncoderConfig] / [VideoDecoderConfig]. They are distinct from the
/// IANA RTP names advertised in SDP (e.g. `'VP8'`, `'H264'` — see
/// `MediaEngine`), which live in their own case-preserved namespace.
abstract final class VideoCodecName {
  VideoCodecName._();

  static const String vp8 = 'vp8';
  static const String vp9 = 'vp9';
  static const String h264 = 'h264';
}

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

// ── VideoEncoder (W3C public API) ───────────────────────────────────────────

/// W3C VideoEncoder — output callback receives encoded chunks.
final class VideoEncoder {
  final void Function(EncodedVideoChunk chunk, EncodedVideoChunkMetadata? metadata) _output;
  final void Function(Object error) _error;

  final CodecFrontendCore<VideoEncoderBackend> _core = CodecFrontendCore('Encoder');

  VideoEncoder({
    required void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?) output,
    required void Function(Object) error,
  })  : _output = output,
        _error = error;

  CodecState get state => _core.state;

  void configure(VideoEncoderConfig config) => _core.configure(
        config.codec,
        () => CodecRegistry.createVideoEncoder(config.codec),
        (backend) => backend
          ..onOutput = _output
          ..onError = _error
          ..configure(config),
      );

  void encode(VideoFrame frame, [VideoEncoderEncodeOptions? options]) =>
      _core.submit((backend) => backend.encode(frame, keyFrame: options?.keyFrame ?? false));

  Future<void> flush() => _core.flush();

  void reset() => _core.reset();

  void close() => _core.close();

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

  final CodecFrontendCore<VideoDecoderBackend> _core = CodecFrontendCore('Decoder');

  VideoDecoder({
    required void Function(VideoFrame) output,
    required void Function(Object) error,
  })  : _output = output,
        _error = error;

  CodecState get state => _core.state;

  void configure(VideoDecoderConfig config) => _core.configure(
        config.codec,
        () => CodecRegistry.createVideoDecoder(config.codec),
        (backend) => backend
          ..onOutput = _output
          ..onError = _error
          ..configure(config),
      );

  void decode(EncodedVideoChunk chunk) => _core.submit((backend) => backend.decode(chunk));

  Future<void> flush() => _core.flush();

  void reset() => _core.reset();

  void close() => _core.close();

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
abstract interface class VideoEncoderBackend implements CodecBackend {
  void configure(VideoEncoderConfig config);
  void encode(VideoFrame frame, {bool keyFrame = false});
  set onOutput(void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?) cb);
  set onError(void Function(Object) cb);
}

/// Codec implementors provide this interface.
/// VideoDecoder delegates to it internally.
abstract interface class VideoDecoderBackend implements CodecBackend {
  void configure(VideoDecoderConfig config);
  void decode(EncodedVideoChunk chunk);
  set onOutput(void Function(VideoFrame) cb);
  set onError(void Function(Object) cb);
}
