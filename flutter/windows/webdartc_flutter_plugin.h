#ifndef FLUTTER_PLUGIN_WEBDARTC_FLUTTER_PLUGIN_H_
#define FLUTTER_PLUGIN_WEBDARTC_FLUTTER_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/texture_registrar.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace webdartc_flutter {

// BT.601 full-range I420 (planar Y, U, V) -> BGRA8 packed pixels.
// `i420` is `width*height + 2*(width/2)*(height/2)` bytes long; `bgra`
// is `width*height*4` bytes long. Exposed for unit testing — the
// conversion is the only piece of meaningful logic in the plugin.
void ConvertI420ToBgra8(const uint8_t* i420, int width, int height,
                        uint8_t* bgra);

class VideoTexture;

// Receives `webdartc_flutter/render` method calls from Dart's
// `ShaderVideoRenderer` and forwards each decoded I420 frame to a
// `flutter::PixelBufferTexture` after a CPU I420 -> BGRA8 conversion.
// The macOS sibling plugin keeps frames as GPU CVPixelBuffers; on
// Windows, `flutter::PixelBufferTexture` is BGRA8-only so the
// conversion happens here.
class WebdartcFlutterPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows* registrar);

  explicit WebdartcFlutterPlugin(flutter::TextureRegistrar* textures);
  virtual ~WebdartcFlutterPlugin();

  WebdartcFlutterPlugin(const WebdartcFlutterPlugin&) = delete;
  WebdartcFlutterPlugin& operator=(const WebdartcFlutterPlugin&) = delete;

  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

 private:
  flutter::TextureRegistrar* textures_;
  std::mutex map_mutex_;
  std::unordered_map<int64_t, std::unique_ptr<VideoTexture>> textures_by_id_;
};

}  // namespace webdartc_flutter

#endif  // FLUTTER_PLUGIN_WEBDARTC_FLUTTER_PLUGIN_H_
