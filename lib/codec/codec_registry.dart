/// Codec backend factory registry.
///
/// Users register codec backends (e.g. VP8 via FFI) and the library
/// creates instances when VideoEncoder/VideoDecoder.configure() is called.
library;

import 'audio_codec.dart';
import 'video_codec.dart';

typedef VideoEncoderFactory = VideoEncoderBackend Function();
typedef VideoDecoderFactory = VideoDecoderBackend Function();
typedef AudioEncoderFactory = AudioEncoderBackend Function();
typedef AudioDecoderFactory = AudioDecoderBackend Function();

/// Registry for codec backend factories.
///
/// Example usage:
/// ```dart
/// CodecRegistry.registerVideoEncoder('vp8', () => MyVp8Encoder());
/// CodecRegistry.registerVideoDecoder('vp8', () => MyVp8Decoder());
/// ```
abstract final class CodecRegistry {
  static final _videoEncoders = <String, VideoEncoderFactory>{};
  static final _videoDecoders = <String, VideoDecoderFactory>{};
  static final _audioEncoders = <String, AudioEncoderFactory>{};
  static final _audioDecoders = <String, AudioDecoderFactory>{};

  static void registerVideoEncoder(String codec, VideoEncoderFactory factory) =>
      _videoEncoders[codec.toLowerCase()] = factory;

  static void registerVideoDecoder(String codec, VideoDecoderFactory factory) =>
      _videoDecoders[codec.toLowerCase()] = factory;

  static void registerAudioEncoder(String codec, AudioEncoderFactory factory) =>
      _audioEncoders[codec.toLowerCase()] = factory;

  static void registerAudioDecoder(String codec, AudioDecoderFactory factory) =>
      _audioDecoders[codec.toLowerCase()] = factory;

  static VideoEncoderBackend? createVideoEncoder(String codec) =>
      _videoEncoders[codec.toLowerCase()]?.call();

  static VideoDecoderBackend? createVideoDecoder(String codec) =>
      _videoDecoders[codec.toLowerCase()]?.call();

  static AudioEncoderBackend? createAudioEncoder(String codec) =>
      _audioEncoders[codec.toLowerCase()]?.call();

  static AudioDecoderBackend? createAudioDecoder(String codec) =>
      _audioDecoders[codec.toLowerCase()]?.call();

  static bool hasVideoEncoder(String codec) =>
      _videoEncoders.containsKey(codec.toLowerCase());

  static bool hasVideoDecoder(String codec) =>
      _videoDecoders.containsKey(codec.toLowerCase());

  static bool hasAudioEncoder(String codec) =>
      _audioEncoders.containsKey(codec.toLowerCase());

  static bool hasAudioDecoder(String codec) =>
      _audioDecoders.containsKey(codec.toLowerCase());
}
