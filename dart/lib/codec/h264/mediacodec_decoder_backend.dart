/// H.264 video decoder backend powered by Android MediaCodec.
///
/// Available on Android. Wraps [MediaCodecH264Decoder] and adapts it to the
/// generic [VideoDecoderBackend]. The decoder is configured without csd —
/// SPS/PPS arrive in-band on key frames (the MediaCodec encoder prepends
/// them) and MediaCodec parses them automatically. Output is converted to
/// packed I420, draining synchronously per `decode`.
library;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import 'mediacodec/mediacodec_helper.dart';

/// MediaCodec-backed H.264 decoder.
final class MediaCodecDecoderBackend implements VideoDecoderBackend {
  MediaCodecH264Decoder? _dec;

  void Function(VideoFrame)? _onOutput;
  void Function(Object)? _onError;

  @override
  set onOutput(void Function(VideoFrame) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoDecoderConfig config) {
    // Nominal dimensions; the decoder re-reads the real size from the output
    // format once the first key frame's SPS is parsed.
    final w = config.codedWidth ?? 640;
    final h = config.codedHeight ?? 480;
    _dec = MediaCodecH264Decoder.create(w, h);
  }

  @override
  void decode(EncodedVideoChunk chunk) {
    final dec = _dec;
    if (dec == null) {
      _onError?.call(StateError('Decoder not configured'));
      return;
    }
    try {
      for (final f in dec.decode(chunk.data, chunk.timestamp)) {
        _onOutput?.call(VideoFrame(
          format: VideoPixelFormat.i420,
          codedWidth: f.width,
          codedHeight: f.height,
          timestamp: f.ptsUs,
          data: f.data,
        ));
      }
    } catch (e) {
      _onError?.call(e);
    }
  }

  @override
  Future<void> flush() async {
    // decode() drains the codec synchronously, so nothing is buffered.
  }

  @override
  void reset() => close();

  @override
  void close() {
    _dec?.close();
    _dec = null;
  }
}
