/// VP8 video decoder backend powered by Android MediaCodec.
///
/// Available on Android when the device provides a VP8 decoder (probed at
/// registration; falls back to the bundled libvpx otherwise). Drives the
/// generic [MediaCodecVideoDecoder] with the `video/x-vnd.on2.vp8` MIME. VP8
/// frames are self-describing (no csd). Output is converted to packed I420,
/// draining synchronously per `decode`.
library;

import '../../media/video_frame.dart';
import '../mediacodec/mediacodec_video.dart';
import '../video_codec.dart';

const String _vp8Mime = 'video/x-vnd.on2.vp8';

/// MediaCodec-backed VP8 decoder.
final class MediaCodecVp8DecoderBackend implements VideoDecoderBackend {
  MediaCodecVideoDecoder? _dec;

  void Function(VideoFrame)? _onOutput;
  void Function(Object)? _onError;

  @override
  set onOutput(void Function(VideoFrame) cb) => _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoDecoderConfig config) {
    // Nominal dimensions; the decoder re-reads the real size from the output
    // format once the first key frame is parsed.
    final w = config.codedWidth ?? 640;
    final h = config.codedHeight ?? 480;
    _dec = MediaCodecVideoDecoder.create(mime: _vp8Mime, width: w, height: h);
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
