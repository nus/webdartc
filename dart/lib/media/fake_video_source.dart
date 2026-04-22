/// Fake video source emitting I420 frames containing the current
/// wall-clock time in milliseconds, rendered with an embedded bitmap font.
///
/// Pure Dart — no Flutter dependency. Useful for media pipeline tests
/// and sample apps without a real camera.
library;

import 'dart:async';
import 'dart:typed_data';

import 'video_frame.dart';

/// A test pattern source emitting I420 video frames. Each frame shows
/// the current wall-clock time in milliseconds as overlay text.
final class FakeVideoSource {
  final int width;
  final int height;
  final double framerate;

  /// `width` and `height` must be even (I420 4:2:0 chroma subsampling).
  FakeVideoSource({
    this.width = 320,
    this.height = 240,
    this.framerate = 30,
  })  : assert(width > 0 && width.isEven),
        assert(height > 0 && height.isEven),
        assert(framerate > 0);

  /// Emits frames at the configured framerate until the stream subscription
  /// is cancelled.
  Stream<VideoFrame> start() async* {
    final periodUs = (1e6 / framerate).round();
    final startUs = DateTime.now().microsecondsSinceEpoch;
    var nextTickUs = startUs;
    while (true) {
      final nowUs = DateTime.now().microsecondsSinceEpoch;
      yield _generateFrame(nowUs ~/ 1000, nowUs - startUs);
      nextTickUs += periodUs;
      final waitUs = nextTickUs - DateTime.now().microsecondsSinceEpoch;
      if (waitUs > 0) await Future<void>.delayed(Duration(microseconds: waitUs));
    }
  }

  /// Deterministic single-frame helper — composes a frame with the given
  /// `nowMs` value instead of reading the wall clock. Useful for tests.
  VideoFrame frameAt(int nowMs) => _generateFrame(nowMs, 0);

  VideoFrame _generateFrame(int nowMs, int timestampUs) {
    final ySize = width * height;
    final uvSize = (width >> 1) * (height >> 1);
    final buffer = Uint8List(ySize + uvSize * 2);

    // Background: dark gray (Y=32), neutral chroma (U=V=128).
    buffer.fillRange(0, ySize, 32);
    buffer.fillRange(ySize, ySize + uvSize * 2, 128);

    _drawText(buffer, '$nowMs ms', x: 16, y: 16, scale: 2);

    return VideoFrame(
      format: VideoPixelFormat.i420,
      codedWidth: width,
      codedHeight: height,
      timestamp: timestampUs,
      data: buffer,
    );
  }

  void _drawText(Uint8List yPlane, String text,
      {required int x, required int y, required int scale}) {
    var px = x;
    for (final unit in text.codeUnits) {
      _drawGlyph(yPlane, _glyph(unit), px, y, scale);
      px += 8 * scale;
    }
  }

  void _drawGlyph(Uint8List yPlane, Uint8List glyph, int x, int y, int scale) {
    for (var row = 0; row < 16; row++) {
      final bits = glyph[row];
      if (bits == 0) continue;
      for (var col = 0; col < 8; col++) {
        if (((bits >> (7 - col)) & 1) == 0) continue;
        for (var dy = 0; dy < scale; dy++) {
          final py = y + row * scale + dy;
          if (py < 0 || py >= height) continue;
          final rowOffset = py * width;
          for (var dx = 0; dx < scale; dx++) {
            final px = x + col * scale + dx;
            if (px < 0 || px >= width) continue;
            yPlane[rowOffset + px] = 235; // bright luma
          }
        }
      }
    }
  }

  Uint8List _glyph(int codeUnit) => _font[codeUnit] ?? _font[0x20]!;
}

// ── Embedded 8×16 bitmap font ───────────────────────────────────────────────
// Public-domain IBM VGA glyphs for digits 0-9, 'm', 's', and space.

final Map<int, Uint8List> _font = {
  0x20: Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
  0x30: Uint8List.fromList([
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xCE, 0xDE, 0xF6, //
    0xE6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x31: Uint8List.fromList([
    0x00, 0x00, 0x18, 0x38, 0x78, 0x18, 0x18, 0x18, //
    0x18, 0x18, 0x18, 0x7E, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x32: Uint8List.fromList([
    0x00, 0x00, 0x7C, 0xC6, 0x06, 0x0C, 0x18, 0x30, //
    0x60, 0xC0, 0xC6, 0xFE, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x33: Uint8List.fromList([
    0x00, 0x00, 0x7C, 0xC6, 0x06, 0x06, 0x3C, 0x06, //
    0x06, 0x06, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x34: Uint8List.fromList([
    0x00, 0x00, 0x0C, 0x1C, 0x3C, 0x6C, 0xCC, 0xFE, //
    0x0C, 0x0C, 0x0C, 0x1E, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x35: Uint8List.fromList([
    0x00, 0x00, 0xFE, 0xC0, 0xC0, 0xC0, 0xFC, 0x06, //
    0x06, 0x06, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x36: Uint8List.fromList([
    0x00, 0x00, 0x38, 0x60, 0xC0, 0xC0, 0xFC, 0xC6, //
    0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x37: Uint8List.fromList([
    0x00, 0x00, 0xFE, 0xC6, 0x06, 0x0C, 0x18, 0x30, //
    0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x38: Uint8List.fromList([
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7C, 0xC6, //
    0xC6, 0xC6, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x39: Uint8List.fromList([
    0x00, 0x00, 0x7C, 0xC6, 0xC6, 0xC6, 0x7E, 0x06, //
    0x06, 0x06, 0x0C, 0x78, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x6D: Uint8List.fromList([
    0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0xFE, 0xD6, //
    0xD6, 0xD6, 0xD6, 0xD6, 0x00, 0x00, 0x00, 0x00,
  ]),
  0x73: Uint8List.fromList([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0xC6, 0x60, //
    0x38, 0x0C, 0xC6, 0x7C, 0x00, 0x00, 0x00, 0x00,
  ]),
};
