// Unit tests for the I420 -> BGRA8 converter used by the Windows plugin.
//
// The conversion is the only piece of non-trivial logic in the plugin
// (everything else is method-channel plumbing). The tests cover the
// primary color extremes plus a 2x2 chroma-subsampling sanity check.

#include "webdartc_flutter_plugin.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

namespace webdartc_flutter {
namespace {

// `n` BGRA8 pixels' worth of buffer size (4 bytes per pixel).
constexpr size_t Bgra8Size(int width, int height) {
  return static_cast<size_t>(width) * height * 4;
}

// I420 buffer size for `width`x`height` (planar Y + half-res U + half-res V).
constexpr size_t I420Size(int width, int height) {
  return static_cast<size_t>(width) * height
      + 2 * static_cast<size_t>(width / 2) * (height / 2);
}

// Fill a 2x2 I420 block where every Y, U, V sample has the same value.
// Returns a buffer that ConvertI420ToBgra8 can consume directly.
std::vector<uint8_t> SolidI420(uint8_t y, uint8_t u, uint8_t v) {
  std::vector<uint8_t> buf(I420Size(2, 2));
  buf[0] = buf[1] = buf[2] = buf[3] = y;   // 2x2 Y plane
  buf[4] = u;                              // 1x1 U plane (4:2:0)
  buf[5] = v;                              // 1x1 V plane
  return buf;
}

// BT.601 full-range reference (matches the converter's integer math):
//   r = y + 1.402*(v-128)
//   g = y - 0.344*(u-128) - 0.714*(v-128)
//   b = y + 1.772*(u-128)
struct Bgra {
  uint8_t b, g, r, a;
};

Bgra ExpectedPixel(uint8_t y, uint8_t u, uint8_t v) {
  const int du = u - 128;
  const int dv = v - 128;
  const int r = y + ((359 * dv) >> 8);
  const int g = y - ((88 * du + 183 * dv) >> 8);
  const int b = y + ((454 * du) >> 8);
  auto clamp = [](int x) {
    return static_cast<uint8_t>(x < 0 ? 0 : (x > 255 ? 255 : x));
  };
  return {clamp(b), clamp(g), clamp(r), 0xFF};
}

::testing::AssertionResult PixelMatches(const uint8_t* bgra, Bgra expected) {
  if (bgra[0] == expected.b && bgra[1] == expected.g &&
      bgra[2] == expected.r && bgra[3] == expected.a) {
    return ::testing::AssertionSuccess();
  }
  return ::testing::AssertionFailure()
      << "BGRA pixel mismatch: got (b=" << +bgra[0] << " g=" << +bgra[1]
      << " r=" << +bgra[2] << " a=" << +bgra[3] << "), expected (b="
      << +expected.b << " g=" << +expected.g << " r=" << +expected.r
      << " a=" << +expected.a << ")";
}

// Every pixel of a solid (y,u,v) 2x2 block should produce the same BGRA8
// value matching the reference formula.
void CheckSolid(uint8_t y, uint8_t u, uint8_t v) {
  const auto src = SolidI420(y, u, v);
  std::vector<uint8_t> dst(Bgra8Size(2, 2));
  ConvertI420ToBgra8(src.data(), 2, 2, dst.data());
  const Bgra expected = ExpectedPixel(y, u, v);
  for (int p = 0; p < 4; ++p) {
    EXPECT_TRUE(PixelMatches(dst.data() + p * 4, expected))
        << "at pixel index " << p << " for Y=" << +y << " U=" << +u
        << " V=" << +v;
  }
}

TEST(ConvertI420ToBgra8, BlackProducesBlackWithAlpha) {
  CheckSolid(/*y=*/0, /*u=*/128, /*v=*/128);
}

TEST(ConvertI420ToBgra8, WhiteFullRange) {
  CheckSolid(/*y=*/255, /*u=*/128, /*v=*/128);
}

// BT.601 primaries: pure R / G / B in YUV space.
TEST(ConvertI420ToBgra8, PrimaryRed) {
  // R = 76, G = 0, B = 0 -> Y ≈ 76, U ≈ 84, V ≈ 255 (full range).
  CheckSolid(/*y=*/76, /*u=*/84, /*v=*/255);
}

TEST(ConvertI420ToBgra8, PrimaryGreen) {
  // G = 150 alone -> Y ≈ 150, U ≈ 43, V ≈ 21.
  CheckSolid(/*y=*/150, /*u=*/43, /*v=*/21);
}

TEST(ConvertI420ToBgra8, PrimaryBlue) {
  // B = 29 alone -> Y ≈ 29, U ≈ 255, V ≈ 107.
  CheckSolid(/*y=*/29, /*u=*/255, /*v=*/107);
}

// Chroma subsampling: a 2x2 source with two distinct Y values but a
// single U/V pair should produce two corresponding luma steps in BGRA
// (and the U/V contribution is shared by all four pixels).
TEST(ConvertI420ToBgra8, ChromaSharedAcross2x2Block) {
  std::vector<uint8_t> src(I420Size(2, 2));
  src[0] = 80;    // top-left Y
  src[1] = 120;   // top-right Y
  src[2] = 160;   // bottom-left Y
  src[3] = 200;   // bottom-right Y
  src[4] = 200;   // shared U (offset toward blue)
  src[5] = 50;    // shared V (offset away from red)

  std::vector<uint8_t> dst(Bgra8Size(2, 2));
  ConvertI420ToBgra8(src.data(), 2, 2, dst.data());

  EXPECT_TRUE(PixelMatches(dst.data() + 0, ExpectedPixel(80, 200, 50)));
  EXPECT_TRUE(PixelMatches(dst.data() + 4, ExpectedPixel(120, 200, 50)));
  EXPECT_TRUE(PixelMatches(dst.data() + 8, ExpectedPixel(160, 200, 50)));
  EXPECT_TRUE(PixelMatches(dst.data() + 12, ExpectedPixel(200, 200, 50)));
}

// Buffer addressing: the converter must not overwrite past
// width*height*4 bytes and must read exactly the I420 layout.
TEST(ConvertI420ToBgra8, DoesNotOverrunDestination) {
  constexpr int W = 4, H = 4;
  std::vector<uint8_t> src(I420Size(W, H), 128);  // gray-ish
  std::vector<uint8_t> dst(Bgra8Size(W, H) + 8, 0xAA);
  ConvertI420ToBgra8(src.data(), W, H, dst.data());
  for (size_t i = Bgra8Size(W, H); i < dst.size(); ++i) {
    EXPECT_EQ(dst[i], 0xAA) << "guard byte " << i << " was overwritten";
  }
}

}  // namespace
}  // namespace webdartc_flutter
