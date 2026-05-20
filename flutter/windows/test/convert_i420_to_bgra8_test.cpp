#include "webdartc_flutter_plugin.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace webdartc_flutter {
namespace {

constexpr size_t Bgra8Size(int width, int height) {
  return static_cast<size_t>(width) * height * 4;
}

constexpr size_t I420Size(int width, int height) {
  return static_cast<size_t>(width) * height
      + 2 * static_cast<size_t>(width / 2) * (height / 2);
}

std::vector<uint8_t> SolidI420(uint8_t y, uint8_t u, uint8_t v) {
  std::vector<uint8_t> buf(I420Size(2, 2));
  buf[0] = buf[1] = buf[2] = buf[3] = y;
  buf[4] = u;
  buf[5] = v;
  return buf;
}

struct Bgra {
  uint8_t b, g, r, a;
};

// BT.601 full-range reference (matches the converter's integer math):
//   r = y + 1.402*(v-128)
//   g = y - 0.344*(u-128) - 0.714*(v-128)
//   b = y + 1.772*(u-128)
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
  CheckSolid(0, 128, 128);
}

TEST(ConvertI420ToBgra8, WhiteFullRange) {
  CheckSolid(255, 128, 128);
}

TEST(ConvertI420ToBgra8, PrimaryRed) {
  CheckSolid(76, 84, 255);
}

TEST(ConvertI420ToBgra8, PrimaryGreen) {
  CheckSolid(150, 43, 21);
}

TEST(ConvertI420ToBgra8, PrimaryBlue) {
  CheckSolid(29, 255, 107);
}

TEST(ConvertI420ToBgra8, ChromaSharedAcross2x2Block) {
  std::vector<uint8_t> src(I420Size(2, 2));
  src[0] = 80;
  src[1] = 120;
  src[2] = 160;
  src[3] = 200;
  src[4] = 200;
  src[5] = 50;

  std::vector<uint8_t> dst(Bgra8Size(2, 2));
  ConvertI420ToBgra8(src.data(), 2, 2, dst.data());

  EXPECT_TRUE(PixelMatches(dst.data() + 0, ExpectedPixel(80, 200, 50)));
  EXPECT_TRUE(PixelMatches(dst.data() + 4, ExpectedPixel(120, 200, 50)));
  EXPECT_TRUE(PixelMatches(dst.data() + 8, ExpectedPixel(160, 200, 50)));
  EXPECT_TRUE(PixelMatches(dst.data() + 12, ExpectedPixel(200, 200, 50)));
}

TEST(ConvertI420ToBgra8, DoesNotOverrunDestination) {
  constexpr int W = 4, H = 4;
  std::vector<uint8_t> src(I420Size(W, H), 128);
  std::vector<uint8_t> dst(Bgra8Size(W, H) + 8, 0xAA);
  ConvertI420ToBgra8(src.data(), W, H, dst.data());
  for (size_t i = Bgra8Size(W, H); i < dst.size(); ++i) {
    EXPECT_EQ(dst[i], 0xAA) << "guard byte " << i << " was overwritten";
  }
}

}  // namespace
}  // namespace webdartc_flutter
