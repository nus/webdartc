#ifndef WEBDARTC_VT_HELPER_H
#define WEBDARTC_VT_HELPER_H

#include <stdint.h>

#if _WIN32
#define WEBDARTC_VT_EXPORT __declspec(dllexport)
#else
#define WEBDARTC_VT_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles.
typedef struct WvtEncoder WvtEncoder;
typedef struct WvtEncoderOutput WvtEncoderOutput;
typedef struct WvtDecoder WvtDecoder;
typedef struct WvtDecodedFrame WvtDecodedFrame;

// Returns the ABI version of this helper.
WEBDARTC_VT_EXPORT int32_t webdartc_vt_helper_abi_version(void);

// ── Encoder ────────────────────────────────────────────────────────────────

// Returns NULL on failure. `keyframe_interval` is the max gap between forced
// IDRs, in frames.
WEBDARTC_VT_EXPORT WvtEncoder* wvt_encoder_create(
    int32_t width, int32_t height, int32_t bitrate, int32_t fps,
    int32_t keyframe_interval);

// Feeds an I420 frame. Plane pointers must remain valid only for this call.
// After this call, completed frames are available via wvt_encoder_drain_one.
// Returns 0 on success, negative on failure.
WEBDARTC_VT_EXPORT int32_t wvt_encoder_encode(
    WvtEncoder* enc,
    const uint8_t* y, const uint8_t* u, const uint8_t* v,
    int32_t y_stride, int32_t uv_stride,
    int64_t pts_us, int32_t force_keyframe);

// Returns the next queued encoded output, or NULL if the queue is empty.
// Caller owns the returned handle and must release it via wvt_encoder_output_free.
WEBDARTC_VT_EXPORT WvtEncoderOutput* wvt_encoder_drain_one(WvtEncoder* enc);

WEBDARTC_VT_EXPORT int32_t wvt_encoder_output_size(WvtEncoderOutput* out);
WEBDARTC_VT_EXPORT int32_t wvt_encoder_output_is_keyframe(WvtEncoderOutput* out);
WEBDARTC_VT_EXPORT int64_t wvt_encoder_output_pts_us(WvtEncoderOutput* out);
WEBDARTC_VT_EXPORT const uint8_t* wvt_encoder_output_data(WvtEncoderOutput* out);
WEBDARTC_VT_EXPORT void wvt_encoder_output_free(WvtEncoderOutput* out);

WEBDARTC_VT_EXPORT void wvt_encoder_destroy(WvtEncoder* enc);

// ── Decoder ────────────────────────────────────────────────────────────────

// Creates an empty decoder. The VT session is lazily created on the first
// frame containing SPS/PPS.
WEBDARTC_VT_EXPORT WvtDecoder* wvt_decoder_create(void);

// Feeds an Annex B buffer. If it contains SPS/PPS, the decoder session is
// initialized (or reconfigured). Returns 0 on success, negative on error.
WEBDARTC_VT_EXPORT int32_t wvt_decoder_decode(
    WvtDecoder* dec,
    const uint8_t* annex_b, int32_t annex_b_size,
    int64_t pts_us);

// Returns the next decoded I420 frame, or NULL if the queue is empty.
WEBDARTC_VT_EXPORT WvtDecodedFrame* wvt_decoder_drain_one(WvtDecoder* dec);

WEBDARTC_VT_EXPORT int32_t wvt_decoded_frame_width(WvtDecodedFrame* f);
WEBDARTC_VT_EXPORT int32_t wvt_decoded_frame_height(WvtDecodedFrame* f);
WEBDARTC_VT_EXPORT int64_t wvt_decoded_frame_pts_us(WvtDecodedFrame* f);
WEBDARTC_VT_EXPORT int32_t wvt_decoded_frame_size(WvtDecodedFrame* f);
WEBDARTC_VT_EXPORT const uint8_t* wvt_decoded_frame_data(WvtDecodedFrame* f);
WEBDARTC_VT_EXPORT void wvt_decoded_frame_free(WvtDecodedFrame* f);

WEBDARTC_VT_EXPORT void wvt_decoder_destroy(WvtDecoder* dec);

#ifdef __cplusplus
}
#endif

#endif
