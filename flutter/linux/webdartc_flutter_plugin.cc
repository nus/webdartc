#include "include/webdartc_flutter/webdartc_flutter_plugin.h"

#include <flutter_linux/flutter_linux.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

// ── I420 → RGBA8 ───────────────────────────────────────────────────────────
//
// BT.601 full-range YUV -> RGBA8, 8.8 fixed-point integer math. Mirrors the
// Windows plugin's `ConvertI420ToBgra8` (and the Android one) — the
// FakeVideoSource / OpenH264 decoder feed full-range I420 — but emits RGBA
// byte order because Flutter's GLES compositor samples `GL_RGBA` here, vs.
// the BGRA `PixelBufferTexture` on Windows.
static void ConvertI420ToRgba8(const uint8_t* i420, int width, int height,
                               uint8_t* rgba) {
  const uint8_t* y_plane = i420;
  const uint8_t* u_plane = i420 + static_cast<size_t>(width) * height;
  const uint8_t* v_plane =
      u_plane + static_cast<size_t>(width / 2) * (height / 2);
  const int uv_stride = width / 2;
  for (int row = 0; row < height; ++row) {
    const uint8_t* y_row = y_plane + static_cast<size_t>(row) * width;
    const uint8_t* u_row = u_plane + static_cast<size_t>(row / 2) * uv_stride;
    const uint8_t* v_row = v_plane + static_cast<size_t>(row / 2) * uv_stride;
    uint8_t* dst = rgba + static_cast<size_t>(row) * width * 4;
    for (int col = 0; col < width; ++col) {
      const int y = y_row[col];
      const int u = u_row[col / 2] - 128;
      const int v = v_row[col / 2] - 128;
      // r = y + 1.402*v, g = y - 0.344*u - 0.714*v, b = y + 1.772*u
      const int r = y + ((359 * v) >> 8);
      const int g = y - ((88 * u + 183 * v) >> 8);
      const int b = y + ((454 * u) >> 8);
      dst[col * 4 + 0] = static_cast<uint8_t>(std::clamp(r, 0, 255));
      dst[col * 4 + 1] = static_cast<uint8_t>(std::clamp(g, 0, 255));
      dst[col * 4 + 2] = static_cast<uint8_t>(std::clamp(b, 0, 255));
      dst[col * 4 + 3] = 0xFF;
    }
  }
}

// ── Video texture ──────────────────────────────────────────────────────────
//
// One `FlPixelBufferTexture` per `ShaderVideoRenderer`. `UpdateI420` (UI
// thread, via the method channel) fills `rgba_`; `copy_pixels` (raster
// thread) hands it back to Flutter. The buffer is guarded by `mutex_`. As on
// Windows, the lock is not held across Flutter's GL upload, so a concurrent
// update can tear a frame — harmless, and the demo's fixed frame size means
// the buffer never reallocates after the first frame.

G_DECLARE_FINAL_TYPE(WebdartcVideoTexture, webdartc_video_texture, WEBDARTC,
                     VIDEO_TEXTURE, FlPixelBufferTexture)

struct _WebdartcVideoTexture {
  FlPixelBufferTexture parent_instance;
  GMutex mutex;
  std::vector<uint8_t>* rgba;
  uint32_t width;
  uint32_t height;
};

G_DEFINE_TYPE(WebdartcVideoTexture, webdartc_video_texture,
              fl_pixel_buffer_texture_get_type())

// `copy_pixels` runs on the raster thread and must hand back an RGBA buffer
// that outlives the call (Flutter reads it before the next tick). `width` /
// `height` arrive holding the canvas size; we overwrite them with the frame's
// real dimensions.
static gboolean webdartc_video_texture_copy_pixels(
    FlPixelBufferTexture* texture, const uint8_t** out_buffer, uint32_t* width,
    uint32_t* height, GError** error) {
  WebdartcVideoTexture* self = WEBDARTC_VIDEO_TEXTURE(texture);
  g_mutex_lock(&self->mutex);
  if (self->rgba->empty() || self->width == 0 || self->height == 0) {
    g_mutex_unlock(&self->mutex);
    g_set_error(error, g_quark_from_static_string("webdartc_flutter"), 0,
                "no frame available yet");
    return FALSE;
  }
  *out_buffer = self->rgba->data();
  *width = self->width;
  *height = self->height;
  g_mutex_unlock(&self->mutex);
  return TRUE;
}

static void webdartc_video_texture_dispose(GObject* object) {
  WebdartcVideoTexture* self = WEBDARTC_VIDEO_TEXTURE(object);
  if (self->rgba != nullptr) {
    delete self->rgba;
    self->rgba = nullptr;
  }
  g_mutex_clear(&self->mutex);
  G_OBJECT_CLASS(webdartc_video_texture_parent_class)->dispose(object);
}

static void webdartc_video_texture_class_init(
    WebdartcVideoTextureClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = webdartc_video_texture_dispose;
  FL_PIXEL_BUFFER_TEXTURE_CLASS(klass)->copy_pixels =
      webdartc_video_texture_copy_pixels;
}

static void webdartc_video_texture_init(WebdartcVideoTexture* self) {
  g_mutex_init(&self->mutex);
  self->rgba = new std::vector<uint8_t>();
  self->width = 0;
  self->height = 0;
}

static WebdartcVideoTexture* webdartc_video_texture_new() {
  return WEBDARTC_VIDEO_TEXTURE(
      g_object_new(webdartc_video_texture_get_type(), nullptr));
}

static void webdartc_video_texture_update_i420(WebdartcVideoTexture* self,
                                               const uint8_t* data,
                                               size_t data_size, int width,
                                               int height) {
  if (width <= 0 || height <= 0) return;
  const size_t y_size = static_cast<size_t>(width) * height;
  const size_t uv_size = static_cast<size_t>(width / 2) * (height / 2);
  if (data_size < y_size + 2 * uv_size) return;

  g_mutex_lock(&self->mutex);
  self->rgba->resize(static_cast<size_t>(width) * height * 4);
  ConvertI420ToRgba8(data, width, height, self->rgba->data());
  self->width = static_cast<uint32_t>(width);
  self->height = static_cast<uint32_t>(height);
  g_mutex_unlock(&self->mutex);
}

// ── Plugin ───────────────────────────────────────────────────────────────

struct _WebdartcFlutterPlugin {
  GObject parent_instance;
  FlTextureRegistrar* texture_registrar;  // not owned
  FlMethodChannel* channel;
  GHashTable* textures;  // int64 texture id -> WebdartcVideoTexture* (owned)
};

G_DEFINE_TYPE(WebdartcFlutterPlugin, webdartc_flutter_plugin, G_TYPE_OBJECT)

// Dart's `StandardMessageCodec` packs every int as a single 64-bit value here,
// so a plain `fl_value_get_int` covers `textureId` / `width` / `height`.
static gboolean lookup_int(FlValue* args, const char* key, int64_t* out) {
  FlValue* v = fl_value_lookup_string(args, key);
  if (v == nullptr || fl_value_get_type(v) != FL_VALUE_TYPE_INT) return FALSE;
  *out = fl_value_get_int(v);
  return TRUE;
}

static void webdartc_flutter_plugin_handle_method_call(
    WebdartcFlutterPlugin* self, FlMethodCall* method_call) {
  const gchar* method = fl_method_call_get_name(method_call);
  g_autoptr(FlMethodResponse) response = nullptr;

  if (strcmp(method, "create") == 0) {
    WebdartcVideoTexture* tex = webdartc_video_texture_new();
    fl_texture_registrar_register_texture(self->texture_registrar,
                                          FL_TEXTURE(tex));
    int64_t id = fl_texture_get_id(FL_TEXTURE(tex));
    g_hash_table_insert(self->textures, GINT_TO_POINTER(id), tex);
    response = FL_METHOD_RESPONSE(
        fl_method_success_response_new(fl_value_new_int(id)));
  } else if (strcmp(method, "render") == 0) {
    FlValue* args = fl_method_call_get_args(method_call);
    int64_t id;
    int64_t width;
    int64_t height;
    FlValue* data =
        args != nullptr ? fl_value_lookup_string(args, "data") : nullptr;
    if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP ||
        !lookup_int(args, "textureId", &id) ||
        !lookup_int(args, "width", &width) ||
        !lookup_int(args, "height", &height) || data == nullptr ||
        fl_value_get_type(data) != FL_VALUE_TYPE_UINT8_LIST) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "BAD_ARGS", "render requires {textureId, width, height, data}",
          nullptr));
    } else {
      auto* tex = static_cast<WebdartcVideoTexture*>(
          g_hash_table_lookup(self->textures, GINT_TO_POINTER(id)));
      if (tex == nullptr) {
        response = FL_METHOD_RESPONSE(fl_method_error_response_new(
            "NO_TEXTURE", "unknown textureId", nullptr));
      } else {
        webdartc_video_texture_update_i420(
            tex, fl_value_get_uint8_list(data), fl_value_get_length(data),
            static_cast<int>(width), static_cast<int>(height));
        fl_texture_registrar_mark_texture_frame_available(
            self->texture_registrar, FL_TEXTURE(tex));
        response =
            FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
      }
    }
  } else if (strcmp(method, "dispose") == 0) {
    FlValue* args = fl_method_call_get_args(method_call);
    int64_t id;
    if (args == nullptr || !lookup_int(args, "textureId", &id)) {
      response = FL_METHOD_RESPONSE(fl_method_error_response_new(
          "BAD_ARGS", "dispose requires {textureId}", nullptr));
    } else {
      auto* tex = static_cast<WebdartcVideoTexture*>(
          g_hash_table_lookup(self->textures, GINT_TO_POINTER(id)));
      if (tex != nullptr) {
        fl_texture_registrar_unregister_texture(self->texture_registrar,
                                                FL_TEXTURE(tex));
        g_hash_table_remove(self->textures, GINT_TO_POINTER(id));
      }
      response = FL_METHOD_RESPONSE(fl_method_success_response_new(nullptr));
    }
  } else {
    response = FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
  }

  g_autoptr(GError) error = nullptr;
  if (!fl_method_call_respond(method_call, response, &error)) {
    g_warning("Failed to send method call response: %s", error->message);
  }
}

static void method_call_cb(FlMethodChannel* channel, FlMethodCall* method_call,
                           gpointer user_data) {
  WebdartcFlutterPlugin* self = WEBDARTC_FLUTTER_PLUGIN(user_data);
  webdartc_flutter_plugin_handle_method_call(self, method_call);
}

static void webdartc_flutter_plugin_dispose(GObject* object) {
  WebdartcFlutterPlugin* self = WEBDARTC_FLUTTER_PLUGIN(object);
  g_clear_pointer(&self->textures, g_hash_table_unref);
  g_clear_object(&self->channel);
  G_OBJECT_CLASS(webdartc_flutter_plugin_parent_class)->dispose(object);
}

static void webdartc_flutter_plugin_class_init(
    WebdartcFlutterPluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose = webdartc_flutter_plugin_dispose;
}

static void webdartc_flutter_plugin_init(WebdartcFlutterPlugin* self) {
  // Keys are texture ids (small ints); values are owned and released with
  // g_object_unref when removed or when the table is destroyed.
  self->textures = g_hash_table_new_full(g_direct_hash, g_direct_equal, nullptr,
                                          g_object_unref);
}

void webdartc_flutter_plugin_register_with_registrar(
    FlPluginRegistrar* registrar) {
  WebdartcFlutterPlugin* plugin = WEBDARTC_FLUTTER_PLUGIN(
      g_object_new(webdartc_flutter_plugin_get_type(), nullptr));

  plugin->texture_registrar =
      fl_plugin_registrar_get_texture_registrar(registrar);

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  plugin->channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar), "webdartc_flutter/render",
      FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(
      plugin->channel, method_call_cb, g_object_ref(plugin), g_object_unref);

  g_object_unref(plugin);
}
