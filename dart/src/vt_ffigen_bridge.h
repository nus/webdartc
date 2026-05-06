// Bridging header for ffigen.
//
// Pulls in the Apple framework headers we need for the pure-Dart
// VideoToolbox helper. Not compiled into the runtime — only consumed
// by `dart run ffigen` to generate Dart FFI bindings.

#ifndef WEBDARTC_VT_FFIGEN_BRIDGE_H
#define WEBDARTC_VT_FFIGEN_BRIDGE_H

#include <CoreFoundation/CoreFoundation.h>
#include <CoreVideo/CoreVideo.h>
#include <CoreMedia/CoreMedia.h>
#include <VideoToolbox/VideoToolbox.h>

#endif
