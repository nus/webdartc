#include "include/webdartc_flutter/webdartc_flutter_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "webdartc_flutter_plugin.h"

void WebdartcFlutterPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  webdartc_flutter::WebdartcFlutterPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
