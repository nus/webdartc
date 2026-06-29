/// Host-runnable unit tests for the generic MediaCodec helper's pure
/// colour-conversion functions (I420 <-> NV12, strided plane unpacking), shared
/// by every MediaCodec video backend (H.264, VP8). These touch no native code —
/// the `libmediandk.so` binding is a lazily-initialised top-level final that
/// these functions never reference — so they run under plain `dart test` on any
/// platform, unlike the on-device MediaCodec codec tests.
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/codec/mediacodec/mediacodec_video.dart';

/// Builds a packed I420 buffer where every sample is a deterministic function
/// of its plane and (row, col), so conversions are easy to assert.
Uint8List _makeI420(int w, int h) {
  final cw = w >> 1, ch = h >> 1;
  final b = Uint8List(w * h + 2 * cw * ch);
  var o = 0;
  for (var r = 0; r < h; r++) {
    for (var c = 0; c < w; c++) {
      b[o++] = (r * w + c) & 0xFF; // Y
    }
  }
  for (var r = 0; r < ch; r++) {
    for (var c = 0; c < cw; c++) {
      b[o++] = (100 + r * cw + c) & 0xFF; // U
    }
  }
  for (var r = 0; r < ch; r++) {
    for (var c = 0; c < cw; c++) {
      b[o++] = (200 + r * cw + c) & 0xFF; // V
    }
  }
  return b;
}

void main() {
  group('i420ToNv12', () {
    test('interleaves U,V as Cb-first semi-planar', () {
      const w = 4, h = 4;
      final i420 = _makeI420(w, h);
      final nv12 = i420ToNv12(i420, w, h);
      final ySize = w * h;
      // Y plane copied verbatim.
      expect(nv12.sublist(0, ySize), i420.sublist(0, ySize));
      // Chroma interleaved U0,V0,U1,V1,...
      final cw = w >> 1, ch = h >> 1;
      final uOff = ySize, vOff = ySize + cw * ch;
      for (var i = 0; i < cw * ch; i++) {
        expect(nv12[ySize + 2 * i], i420[uOff + i], reason: 'U sample $i');
        expect(nv12[ySize + 2 * i + 1], i420[vOff + i], reason: 'V sample $i');
      }
    });
  });

  group('nv12ToI420', () {
    test('round-trips i420ToNv12 (tight stride)', () {
      const w = 8, h = 6;
      final i420 = _makeI420(w, h);
      final nv12 = i420ToNv12(i420, w, h);
      final back = nv12ToI420(nv12, w, h, w, h);
      expect(back, i420);
    });

    test('respects padded stride / slice-height', () {
      const w = 4, h = 4, stride = 6, sliceHeight = 6;
      final cw = w >> 1, ch = h >> 1;
      // Build a strided NV12 source: Y is stride*sliceHeight, UV interleaved
      // starting at that offset, also at `stride` row pitch.
      final src = Uint8List(stride * sliceHeight + stride * (sliceHeight >> 1));
      for (var r = 0; r < h; r++) {
        for (var c = 0; c < w; c++) {
          src[r * stride + c] = (r * w + c) & 0xFF;
        }
      }
      final uvBase = stride * sliceHeight;
      for (var r = 0; r < ch; r++) {
        for (var c = 0; c < cw; c++) {
          src[uvBase + r * stride + 2 * c] = (100 + r * cw + c) & 0xFF; // U
          src[uvBase + r * stride + 2 * c + 1] = (200 + r * cw + c) & 0xFF; // V
        }
      }
      final out = nv12ToI420(src, w, h, stride, sliceHeight);
      expect(out, _makeI420(w, h));
    });
  });

  group('planarToI420', () {
    test('unpacks padded planar layout to tight I420', () {
      const w = 4, h = 4, stride = 8, sliceHeight = 6;
      final cw = w >> 1, ch = h >> 1;
      final cwStride = stride >> 1;
      final ySize = stride * sliceHeight;
      final uSize = cwStride * (sliceHeight >> 1);
      final src = Uint8List(ySize + 2 * uSize);
      for (var r = 0; r < h; r++) {
        for (var c = 0; c < w; c++) {
          src[r * stride + c] = (r * w + c) & 0xFF;
        }
      }
      final uBase = ySize, vBase = ySize + uSize;
      for (var r = 0; r < ch; r++) {
        for (var c = 0; c < cw; c++) {
          src[uBase + r * cwStride + c] = (100 + r * cw + c) & 0xFF;
          src[vBase + r * cwStride + c] = (200 + r * cw + c) & 0xFF;
        }
      }
      final out = planarToI420(src, w, h, stride, sliceHeight);
      expect(out, _makeI420(w, h));
    });
  });
}
