/// W3C VideoFrame — raw video frame data.
/// https://www.w3.org/TR/webcodecs/#videoframe-interface
library;

import 'dart:typed_data';

/// Pixel formats for raw video frames.
enum VideoPixelFormat { i420, nv12, rgba, bgra }

/// A single raw video frame.
final class VideoFrame {
  final VideoPixelFormat format;
  final int codedWidth;
  final int codedHeight;

  /// Presentation timestamp in microseconds.
  final int timestamp;

  /// Duration in microseconds (optional).
  final int? duration;

  /// Raw pixel data.
  final Uint8List data;

  const VideoFrame({
    required this.format,
    required this.codedWidth,
    required this.codedHeight,
    required this.timestamp,
    this.duration,
    required this.data,
  });

  /// Copy pixel data to a new buffer.
  Uint8List copyTo() => Uint8List.fromList(data);

  /// Release resources associated with this frame.
  void close() {}
}
