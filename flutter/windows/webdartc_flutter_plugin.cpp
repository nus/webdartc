#include "webdartc_flutter_plugin.h"

#include <windows.h>

#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <flutter/texture_registrar.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace webdartc_flutter {

// BT.601 full-range YUV -> BGRA8, 8.8 fixed-point integer math.
// FakeVideoSource / VT encoder on the macOS side feeds full-range
// I420 (kCVPixelFormatType_420YpCbCr8BiPlanarFullRange), so this
// matches the macOS plugin's color space.
void ConvertI420ToBgra8(const uint8_t* i420, int width, int height,
                        uint8_t* bgra) {
  const uint8_t* y_plane = i420;
  const uint8_t* u_plane = i420 + static_cast<size_t>(width) * height;
  const uint8_t* v_plane =
      u_plane + static_cast<size_t>(width / 2) * (height / 2);
  const int uv_stride = width / 2;
  for (int row = 0; row < height; ++row) {
    const uint8_t* y_row = y_plane + static_cast<size_t>(row) * width;
    const uint8_t* u_row =
        u_plane + static_cast<size_t>(row / 2) * uv_stride;
    const uint8_t* v_row =
        v_plane + static_cast<size_t>(row / 2) * uv_stride;
    uint8_t* dst = bgra + static_cast<size_t>(row) * width * 4;
    for (int col = 0; col < width; ++col) {
      const int y = y_row[col];
      const int u = u_row[col / 2] - 128;
      const int v = v_row[col / 2] - 128;
      // r = y + 1.402*v, g = y - 0.344*u - 0.714*v, b = y + 1.772*u
      const int r = y + ((359 * v) >> 8);
      const int g = y - ((88 * u + 183 * v) >> 8);
      const int b = y + ((454 * u) >> 8);
      dst[col * 4 + 0] = static_cast<uint8_t>(std::clamp(b, 0, 255));
      dst[col * 4 + 1] = static_cast<uint8_t>(std::clamp(g, 0, 255));
      dst[col * 4 + 2] = static_cast<uint8_t>(std::clamp(r, 0, 255));
      dst[col * 4 + 3] = 0xFF;
    }
  }
}

// One video track's worth of CPU-side texture state. Owns the BGRA8
// scratch buffer that the I420 -> BGRA8 conversion writes into and
// hands a stable `FlutterDesktopPixelBuffer*` back to Flutter's
// raster thread.
class VideoTexture {
 public:
  explicit VideoTexture(flutter::TextureRegistrar* textures)
      : textures_(textures),
        variant_(std::make_unique<flutter::TextureVariant>(
            flutter::PixelBufferTexture(
                [this](size_t /*req_width*/, size_t /*req_height*/) {
                  return CopyPixelBuffer();
                }))) {
    texture_id_ = textures_->RegisterTexture(variant_.get());
  }

  ~VideoTexture() {
    if (texture_id_ != -1) {
      textures_->UnregisterTexture(texture_id_);
    }
  }

  int64_t id() const { return texture_id_; }

  void UpdateI420(const uint8_t* data, size_t data_size, int width,
                  int height) {
    if (width <= 0 || height <= 0) return;
    // I420 byte layout: Y plane (w·h), then U plane ((w/2)·(h/2)), then
    // V plane ((w/2)·(h/2)).
    const size_t y_size = static_cast<size_t>(width) * height;
    const size_t uv_size =
        static_cast<size_t>(width / 2) * (height / 2);
    if (data_size < y_size + 2 * uv_size) return;

    {
      std::lock_guard<std::mutex> lk(buf_mutex_);
      bgra_.resize(static_cast<size_t>(width) * height * 4);
      ConvertI420ToBgra8(data, width, height, bgra_.data());
      width_ = width;
      height_ = height;
    }

    textures_->MarkTextureFrameAvailable(texture_id_);
  }

 private:
  // Flutter's `PixelBufferTexture` callback. Runs on the raster thread
  // — must not block the platform thread that fills `bgra_` via
  // `UpdateI420`.
  const FlutterDesktopPixelBuffer* CopyPixelBuffer() {
    std::lock_guard<std::mutex> lk(buf_mutex_);
    if (bgra_.empty()) return nullptr;
    pixel_buffer_.buffer = bgra_.data();
    pixel_buffer_.width = static_cast<size_t>(width_);
    pixel_buffer_.height = static_cast<size_t>(height_);
    pixel_buffer_.release_context = nullptr;
    pixel_buffer_.release_callback = nullptr;
    return &pixel_buffer_;
  }

  flutter::TextureRegistrar* textures_;
  std::unique_ptr<flutter::TextureVariant> variant_;
  int64_t texture_id_ = -1;
  std::mutex buf_mutex_;
  std::vector<uint8_t> bgra_;
  int width_ = 0;
  int height_ = 0;
  FlutterDesktopPixelBuffer pixel_buffer_ = {};
};

namespace {

// Helpers to pull a typed value out of `flutter::EncodableMap`.
template <typename T>
const T* Get(const flutter::EncodableMap& args, const char* key) {
  auto it = args.find(flutter::EncodableValue(key));
  if (it == args.end()) return nullptr;
  return std::get_if<T>(&it->second);
}

}  // namespace

// static
void WebdartcFlutterPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows* registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "webdartc_flutter/render",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin =
      std::make_unique<WebdartcFlutterPlugin>(registrar->texture_registrar());

  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto& call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

WebdartcFlutterPlugin::WebdartcFlutterPlugin(
    flutter::TextureRegistrar* textures)
    : textures_(textures) {}

WebdartcFlutterPlugin::~WebdartcFlutterPlugin() = default;

void WebdartcFlutterPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  const std::string& method = method_call.method_name();

  if (method == "create") {
    auto tex = std::make_unique<VideoTexture>(textures_);
    const int64_t id = tex->id();
    {
      std::lock_guard<std::mutex> lk(map_mutex_);
      textures_by_id_[id] = std::move(tex);
    }
    result->Success(flutter::EncodableValue(id));
    return;
  }

  if (method == "render") {
    const auto* args = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (!args) {
      result->Error("BAD_ARGS", "render requires a map argument");
      return;
    }
    const auto* id_p = Get<int64_t>(*args, "textureId");
    const auto* width_p = Get<int32_t>(*args, "width");
    const auto* height_p = Get<int32_t>(*args, "height");
    const auto* data_p = Get<std::vector<uint8_t>>(*args, "data");
    if (!id_p || !width_p || !height_p || !data_p) {
      result->Error("BAD_ARGS",
                    "render requires {textureId, width, height, data}");
      return;
    }
    VideoTexture* tex = nullptr;
    {
      std::lock_guard<std::mutex> lk(map_mutex_);
      auto it = textures_by_id_.find(*id_p);
      if (it != textures_by_id_.end()) tex = it->second.get();
    }
    if (!tex) {
      result->Error("NO_TEXTURE", "unknown textureId");
      return;
    }
    tex->UpdateI420(data_p->data(), data_p->size(), *width_p, *height_p);
    result->Success();
    return;
  }

  if (method == "dispose") {
    const auto* args = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (!args) {
      result->Error("BAD_ARGS", "dispose requires a map argument");
      return;
    }
    const auto* id_p = Get<int64_t>(*args, "textureId");
    if (!id_p) {
      result->Error("BAD_ARGS", "dispose requires {textureId}");
      return;
    }
    {
      std::lock_guard<std::mutex> lk(map_mutex_);
      textures_by_id_.erase(*id_p);
    }
    result->Success();
    return;
  }

  result->NotImplemented();
}

}  // namespace webdartc_flutter
