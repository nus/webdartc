// webdartc thin wrapper around libvpx's VP9 encoder + decoder.
// Surface and conventions match webdartc_vp8.h; the only difference is
// the libvpx codec interface selected (vpx_codec_vp9_{cx,dx}).

#ifndef WEBDARTC_VP9_H
#define WEBDARTC_VP9_H

#include <stddef.h>
#include <stdint.h>

#include "webdartc_export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WebdartcVp9Encoder WebdartcVp9Encoder;
typedef struct WebdartcVp9Output WebdartcVp9Output;
typedef struct WebdartcVp9Decoder WebdartcVp9Decoder;
typedef struct WebdartcVp9Frame WebdartcVp9Frame;

// ── Encoder ───────────────────────────────────────────────────────────

WEBDARTC_API WebdartcVp9Encoder *webdartc_vp9_encoder_create(
    int width, int height, int target_bitrate_kbps, int kf_max_dist);
WEBDARTC_API void webdartc_vp9_encoder_destroy(WebdartcVp9Encoder *enc);

WEBDARTC_API int webdartc_vp9_encoder_encode(
    WebdartcVp9Encoder *enc,
    const uint8_t *y, const uint8_t *u, const uint8_t *v,
    int width, int height, int64_t pts_us, int force_keyframe);

WEBDARTC_API WebdartcVp9Output *webdartc_vp9_encoder_drain_one(
    WebdartcVp9Encoder *enc);

WEBDARTC_API const uint8_t *webdartc_vp9_output_data(WebdartcVp9Output *out);
WEBDARTC_API size_t webdartc_vp9_output_size(WebdartcVp9Output *out);
WEBDARTC_API int64_t webdartc_vp9_output_pts_us(WebdartcVp9Output *out);
WEBDARTC_API int webdartc_vp9_output_is_keyframe(WebdartcVp9Output *out);
WEBDARTC_API void webdartc_vp9_output_free(WebdartcVp9Output *out);

WEBDARTC_API const char *webdartc_vp9_get_version_string(void);

// ── Decoder ───────────────────────────────────────────────────────────

WEBDARTC_API WebdartcVp9Decoder *webdartc_vp9_decoder_create(void);
WEBDARTC_API void webdartc_vp9_decoder_destroy(WebdartcVp9Decoder *dec);

WEBDARTC_API int webdartc_vp9_decoder_decode(
    WebdartcVp9Decoder *dec,
    const uint8_t *data, size_t size, int64_t pts_us);

WEBDARTC_API WebdartcVp9Frame *webdartc_vp9_decoder_drain_one(
    WebdartcVp9Decoder *dec);

WEBDARTC_API const uint8_t *webdartc_vp9_frame_data(WebdartcVp9Frame *f);
WEBDARTC_API int webdartc_vp9_frame_width(WebdartcVp9Frame *f);
WEBDARTC_API int webdartc_vp9_frame_height(WebdartcVp9Frame *f);
WEBDARTC_API int64_t webdartc_vp9_frame_pts_us(WebdartcVp9Frame *f);
WEBDARTC_API void webdartc_vp9_frame_free(WebdartcVp9Frame *f);

#ifdef __cplusplus
}
#endif

#endif // WEBDARTC_VP9_H
