library;

import 'package:test/test.dart';
import 'package:webdartc/media/fake_video_source.dart';
import 'package:webdartc/media/video_frame.dart';

void main() {
  group('FakeVideoSource.frameAt', () {
    test('output is I420 with correct dimensions and buffer size', () {
      final src = FakeVideoSource(width: 320, height: 240);
      final frame = src.frameAt(0);
      expect(frame.format, VideoPixelFormat.i420);
      expect(frame.codedWidth, 320);
      expect(frame.codedHeight, 240);
      expect(frame.data.length, 320 * 240 + 2 * (160 * 120));
    });

    test('chroma planes are neutral gray (128) for all samples', () {
      final src = FakeVideoSource(width: 320, height: 240);
      final frame = src.frameAt(12345);
      final ySize = 320 * 240;
      final uvEnd = ySize + 2 * 160 * 120;
      for (var i = ySize; i < uvEnd; i++) {
        expect(frame.data[i], 128, reason: 'chroma byte $i should be 128');
      }
    });

    test('background Y pixels are dark gray (32) away from text area', () {
      final src = FakeVideoSource(width: 320, height: 240);
      final frame = src.frameAt(12345);
      // Bottom area, well below the text strip (y=16..48) regardless of digits.
      for (var py = 100; py < 110; py++) {
        for (var px = 0; px < 320; px++) {
          expect(frame.data[py * 320 + px], 32,
              reason: 'pixel ($px,$py) should be background 32');
        }
      }
    });

    test('digit "0" lights expected Y-plane pixels at scale=2', () {
      // Glyph '0' row 2 = 0x7C = 0b01111100 → cols 1,2,3,4,5 lit.
      // Render layout: x=16, y=16, scale=2, first char '0'.
      // Expected lit pixel coords for that row:
      //   py ∈ {16 + 2*2 + 0, 16 + 2*2 + 1} = {20, 21}
      //   px ∈ {16 + c*2, 16 + c*2 + 1} for c in 1..5
      //        = {18,19, 20,21, 22,23, 24,25, 26,27}
      final src = FakeVideoSource(width: 320, height: 240);
      final frame = src.frameAt(0); // text starts with '0'
      for (final py in [20, 21]) {
        for (final px in [18, 19, 20, 21, 22, 23, 24, 25, 26, 27]) {
          expect(frame.data[py * 320 + px], 235,
              reason: 'pixel ($px,$py) should be lit (Y=235)');
        }
      }
      // Pixels just outside the lit range should still be background.
      expect(frame.data[20 * 320 + 17], 32);
      expect(frame.data[20 * 320 + 28], 32);
    });

    test('different timestamps produce different Y planes (text changed)', () {
      final src = FakeVideoSource(width: 320, height: 240);
      final a = src.frameAt(111);
      final b = src.frameAt(222);
      final yA = a.data.sublist(0, 320 * 240);
      final yB = b.data.sublist(0, 320 * 240);
      expect(yA, isNot(yB));
    });
  });

  test('start() emits frames and advances timestamps', () async {
    final src = FakeVideoSource(width: 160, height: 120, framerate: 60);
    final frames = <VideoFrame>[];
    await for (final f in src.start().take(3)) {
      frames.add(f);
    }
    expect(frames, hasLength(3));
    expect(frames[1].timestamp, greaterThan(frames[0].timestamp));
    expect(frames[2].timestamp, greaterThan(frames[1].timestamp));
  });
}
