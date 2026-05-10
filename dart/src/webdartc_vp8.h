// webdartc thin wrapper around libvpx's VP8 encoder.
//
// libvpx is statically linked into the same shared library as these
// wrappers. Only the `webdartc_vp8_*` symbols below are exported (see
// -fvisibility=hidden in the build hook); every `vpx_*` symbol stays
// internal so it cannot collide with another libvpx copy in the same
// process.
//
// Surface mirrors what dart/lib/codec/vp8/vp8_encoder_backend.dart needs
// today: encoder lifecycle, single encode-and-drain pair, plus a
// version-string accessor for diagnostics. Mirrors webdartc_opus.h's
// shape and the wvt_callback.h drain idiom.

#ifndef WEBDARTC_VP8_H
#define WEBDARTC_VP8_H

#include <stddef.h>
#include <stdint.h>

#include "webdartc_export.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WebdartcVp8Encoder WebdartcVp8Encoder;
typedef struct WebdartcVp8Output WebdartcVp8Output;
typedef struct WebdartcVp8Decoder WebdartcVp8Decoder;
typedef struct WebdartcVp8Frame WebdartcVp8Frame;

// Configure libvpx's timebase to microseconds: callers pass `pts_us`
// values directly into encode and read the same units back from
// webdartc_vp8_output_pts_us.

WEBDARTC_API WebdartcVp8Encoder *webdartc_vp8_encoder_create(
    int width,
    int height,
    int target_bitrate_kbps,
    int kf_max_dist);

WEBDARTC_API void webdartc_vp8_encoder_destroy(WebdartcVp8Encoder *enc);

// Encodes one I420 frame. The Y plane is `width * height` bytes with
// stride `width`; U and V are `(width/2) * (height/2)` bytes with stride
// `width/2`. Returns 0 on success, the libvpx error code (cast to int)
// on failure. Callers must drain via `webdartc_vp8_encoder_drain_one`
// before the next encode.
WEBDARTC_API int webdartc_vp8_encoder_encode(
    WebdartcVp8Encoder *enc,
    const uint8_t *y,
    const uint8_t *u,
    const uint8_t *v,
    int width,
    int height,
    int64_t pts_us,
    int force_keyframe);

// Returns the next encoded packet, or NULL when the encoder has no more
// packets queued for the most recent encode call. Caller owns the
// returned object and MUST release it with
// `webdartc_vp8_output_free`.
WEBDARTC_API WebdartcVp8Output *webdartc_vp8_encoder_drain_one(
    WebdartcVp8Encoder *enc);

WEBDARTC_API const uint8_t *webdartc_vp8_output_data(WebdartcVp8Output *out);
WEBDARTC_API size_t webdartc_vp8_output_size(WebdartcVp8Output *out);
WEBDARTC_API int64_t webdartc_vp8_output_pts_us(WebdartcVp8Output *out);
WEBDARTC_API int webdartc_vp8_output_is_keyframe(WebdartcVp8Output *out);
WEBDARTC_API void webdartc_vp8_output_free(WebdartcVp8Output *out);

// Mirrors `vpx_codec_version_str()`. Useful for asserting which bundled
// libvpx is loaded after a submodule bump. The returned C string is
// owned by libvpx (static storage); do not free.
WEBDARTC_API const char *webdartc_vp8_get_version_string(void);

// ── Decoder ───────────────────────────────────────────────────────────

WEBDARTC_API WebdartcVp8Decoder *webdartc_vp8_decoder_create(void);
WEBDARTC_API void webdartc_vp8_decoder_destroy(WebdartcVp8Decoder *dec);

// Submits one encoded frame to the decoder. Returns 0 on success, the
// libvpx error code (cast to int) on failure. Callers must drain via
// `webdartc_vp8_decoder_drain_one` before the next decode call.
WEBDARTC_API int webdartc_vp8_decoder_decode(
    WebdartcVp8Decoder *dec,
    const uint8_t *data,
    size_t size,
    int64_t pts_us);

// Returns the next decoded frame (I420), or NULL when no more frames are
// queued for the most recent decode call. Caller owns the returned
// object and MUST release it with `webdartc_vp8_frame_free`.
WEBDARTC_API WebdartcVp8Frame *webdartc_vp8_decoder_drain_one(
    WebdartcVp8Decoder *dec);

// Frame accessors. The pointer returned by `_data` is contiguous I420
// (Y, then U, then V — each plane laid out tightly without stride
// padding) of length width*height*3/2 bytes.
WEBDARTC_API const uint8_t *webdartc_vp8_frame_data(WebdartcVp8Frame *f);
WEBDARTC_API int webdartc_vp8_frame_width(WebdartcVp8Frame *f);
WEBDARTC_API int webdartc_vp8_frame_height(WebdartcVp8Frame *f);
WEBDARTC_API int64_t webdartc_vp8_frame_pts_us(WebdartcVp8Frame *f);
WEBDARTC_API void webdartc_vp8_frame_free(WebdartcVp8Frame *f);

#ifdef __cplusplus
}
#endif

#endif // WEBDARTC_VP8_H
