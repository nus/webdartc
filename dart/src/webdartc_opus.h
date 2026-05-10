// webdartc thin wrapper around libopus.
//
// libopus is statically linked into the same dylib as these wrappers. Only
// the `webdartc_opus_*` symbols below are exported (see -fvisibility=hidden
// in the build hook); every `opus_*` symbol stays internal so it cannot
// collide with another libopus copy in the same process.
//
// The surface is exactly what dart/lib/codec/opus/ uses today — encoder
// and decoder lifecycle plus raw encode / decode. The variadic
// `opus_encoder_ctl` is exposed only in its 3-arg integer form because
// that's the only shape webdartc invokes (OPUS_SET_BITRATE_REQUEST).

#ifndef WEBDARTC_OPUS_H
#define WEBDARTC_OPUS_H

#include <stdint.h>

#include "webdartc_export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WebdartcOpusEncoder WebdartcOpusEncoder;
typedef struct WebdartcOpusDecoder WebdartcOpusDecoder;

// Subset of libopus constants currently used by Dart. Values mirror
// opus_defines.h so the wrapper is a transparent passthrough; add more
// when a new call site needs them.
#define WEBDARTC_OPUS_OK                  0
#define WEBDARTC_OPUS_APPLICATION_VOIP    2048
#define WEBDARTC_OPUS_SET_BITRATE_REQUEST 4002

WEBDARTC_API WebdartcOpusEncoder *webdartc_opus_encoder_create(
    int32_t sample_rate, int channels, int application, int *error);
WEBDARTC_API void webdartc_opus_encoder_destroy(WebdartcOpusEncoder *st);

WEBDARTC_API int32_t webdartc_opus_encode(
    WebdartcOpusEncoder *st,
    const int16_t *pcm,
    int frame_size,
    unsigned char *data,
    int32_t max_data_bytes);

// 3-arg integer CTL form (the only shape webdartc invokes).
WEBDARTC_API int webdartc_opus_encoder_ctl_int(
    WebdartcOpusEncoder *st, int request, int32_t value);

WEBDARTC_API WebdartcOpusDecoder *webdartc_opus_decoder_create(
    int32_t sample_rate, int channels, int *error);
WEBDARTC_API void webdartc_opus_decoder_destroy(WebdartcOpusDecoder *st);

WEBDARTC_API int webdartc_opus_decode(
    WebdartcOpusDecoder *st,
    const unsigned char *data,
    int32_t len,
    int16_t *pcm,
    int frame_size,
    int decode_fec);

// Mirrors libopus's `opus_get_version_string()`. Useful for asserting
// which bundled libopus build is loaded after a submodule bump.
// The returned C string is owned by libopus (static storage); do not free.
WEBDARTC_API const char *webdartc_opus_get_version_string(void);

#ifdef __cplusplus
}
#endif

#endif // WEBDARTC_OPUS_H
