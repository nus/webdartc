#ifndef FLUTTER_PLUGIN_WEBDARTC_FLUTTER_PLUGIN_H_
#define FLUTTER_PLUGIN_WEBDARTC_FLUTTER_PLUGIN_H_

#include <flutter_linux/flutter_linux.h>

G_BEGIN_DECLS

#ifdef FLUTTER_PLUGIN_IMPL
#define FLUTTER_PLUGIN_EXPORT __attribute__((visibility("default")))
#else
#define FLUTTER_PLUGIN_EXPORT
#endif

#define WEBDARTC_FLUTTER_TYPE_PLUGIN (webdartc_flutter_plugin_get_type())

G_DECLARE_FINAL_TYPE(WebdartcFlutterPlugin, webdartc_flutter_plugin, WEBDARTC,
                     FLUTTER_PLUGIN, GObject)

FLUTTER_PLUGIN_EXPORT void webdartc_flutter_plugin_register_with_registrar(
    FlPluginRegistrar* registrar);

G_END_DECLS

#endif  // FLUTTER_PLUGIN_WEBDARTC_FLUTTER_PLUGIN_H_
