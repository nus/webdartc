// Single source of truth for the symbol-export attribute used by every
// `webdartc_*` C wrapper. PE's default-hidden flips to default-exported
// once we use __declspec, so statically-linked libvpx / libopus
// symbols stay internal the same way `-fvisibility=hidden` keeps them
// internal on Unix.

#ifndef WEBDARTC_EXPORT_H
#define WEBDARTC_EXPORT_H

#if _WIN32
#define WEBDARTC_API __declspec(dllexport)
#else
#define WEBDARTC_API __attribute__((visibility("default")))
#endif

#endif // WEBDARTC_EXPORT_H
