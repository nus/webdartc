/// Generic video decoder backend powered by Android MediaCodec.
///
/// Available on Android. Drives the [MediaCodecVideoDecoder] for a given MIME
/// (`video/avc` for H.264, `video/x-vnd.on2.vp8` for VP8, …) and adapts it to
/// the W3C-style [VideoDecoderBackend]. Decoding is codec-agnostic — compressed
/// frames in (H.264 SPS/PPS arrive in-band on key frames; VP8 frames are
/// self-describing), packed I420 out, drained synchronously per `decode` — so a
/// single class serves every MediaCodec video codec, parameterised only by MIME.
library;

import '../../media/video_frame.dart';
import '../video_codec.dart';
import 'mediacodec_video.dart';

final class MediaCodecVideoDecoderBackend implements VideoDecoderBackend {
  final String _mime;
  MediaCodecVideoDecoder? _dec;

  void Function(VideoFrame)? _onOutput;
  void Function(Object)? _onError;

  MediaCodecVideoDecoderBackend(this._mime);

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
    _dec = MediaCodecVideoDecoder.create(mime: _mime, width: w, height: h);
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
