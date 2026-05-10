#include "webdartc_vp8.h"

#include <stdlib.h>
#include <string.h>

#include <vpx/vpx_encoder.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>

struct WebdartcVp8Encoder {
  vpx_codec_ctx_t ctx;
  vpx_image_t img;
  // Held across drain_one calls so consecutive drains continue from
  // where the last one left off; reset at the top of each encode.
  vpx_codec_iter_t drain_iter;
  int initialized;
};

// Stored as a flexible array member after the struct so a single malloc
// covers both metadata and payload.
struct WebdartcVp8Output {
  size_t size;
  int64_t pts_us;
  int is_keyframe;
  // Followed by `size` bytes of encoded data.
};

static inline uint8_t *output_payload(WebdartcVp8Output *out) {
  return (uint8_t *)(out + 1);
}

// Copies a video plane into a tightly-packed destination buffer,
// returning the new write cursor. Falls back to per-row memcpy only
// when libvpx's stride exceeds the visible plane width.
static uint8_t *copy_plane(uint8_t *dst, const uint8_t *src, int stride,
                           int width, int height) {
  if (stride == width) {
    const size_t bytes = (size_t)width * (size_t)height;
    memcpy(dst, src, bytes);
    return dst + bytes;
  }
  for (int row = 0; row < height; row++) {
    memcpy(dst, src + row * stride, (size_t)width);
    dst += width;
  }
  return dst;
}

WebdartcVp8Encoder *webdartc_vp8_encoder_create(
    int width, int height, int target_bitrate_kbps, int kf_max_dist) {
  WebdartcVp8Encoder *enc = calloc(1, sizeof(*enc));
  if (!enc) return NULL;

  vpx_codec_enc_cfg_t cfg;
  vpx_codec_iface_t *iface = vpx_codec_vp8_cx();
  if (vpx_codec_enc_config_default(iface, &cfg, 0) != VPX_CODEC_OK) {
    free(enc);
    return NULL;
  }
  cfg.g_w = (unsigned int)width;
  cfg.g_h = (unsigned int)height;
  // Microsecond timebase so callers can pass µs pts values directly.
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = 1000000;
  cfg.rc_target_bitrate = (unsigned int)target_bitrate_kbps;
  cfg.g_error_resilient = 1;
  cfg.kf_max_dist = (unsigned int)kf_max_dist;

  if (vpx_codec_enc_init_ver(
          &enc->ctx, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION) !=
      VPX_CODEC_OK) {
    free(enc);
    return NULL;
  }
  enc->initialized = 1;
  return enc;
}

void webdartc_vp8_encoder_destroy(WebdartcVp8Encoder *enc) {
  if (!enc) return;
  if (enc->initialized) {
    vpx_codec_destroy(&enc->ctx);
  }
  free(enc);
}

int webdartc_vp8_encoder_encode(
    WebdartcVp8Encoder *enc,
    const uint8_t *y, const uint8_t *u, const uint8_t *v,
    int width, int height, int64_t pts_us, int force_keyframe) {
  if (!enc) return VPX_CODEC_INVALID_PARAM;

  // vpx_img_wrap takes a single contiguous I420 buffer and computes
  // plane offsets from the layout. Our caller hands us potentially
  // non-contiguous Y/U/V pointers, so set the image planes manually
  // after a wrap of the Y plane.
  vpx_img_wrap(&enc->img, VPX_IMG_FMT_I420, width, height, 1, (uint8_t *)y);
  enc->img.planes[VPX_PLANE_Y] = (uint8_t *)y;
  enc->img.planes[VPX_PLANE_U] = (uint8_t *)u;
  enc->img.planes[VPX_PLANE_V] = (uint8_t *)v;
  enc->img.stride[VPX_PLANE_Y] = width;
  enc->img.stride[VPX_PLANE_U] = width >> 1;
  enc->img.stride[VPX_PLANE_V] = width >> 1;

  enc->drain_iter = NULL;
  const int flags = force_keyframe ? VPX_EFLAG_FORCE_KF : 0;
  // Duration is a single tick of g_timebase; with a µs timebase that's
  // 1 µs which is fine — libvpx uses it only to scale the bitrate
  // controller's view of frame interval, and we already set
  // rc_target_bitrate explicitly.
  return (int)vpx_codec_encode(
      &enc->ctx, &enc->img, pts_us, 1, flags, VPX_DL_REALTIME);
}

WebdartcVp8Output *webdartc_vp8_encoder_drain_one(WebdartcVp8Encoder *enc) {
  if (!enc) return NULL;
  while (1) {
    const vpx_codec_cx_pkt_t *pkt =
        vpx_codec_get_cx_data(&enc->ctx, &enc->drain_iter);
    if (!pkt) return NULL;
    if (pkt->kind != VPX_CODEC_CX_FRAME_PKT) continue;

    const size_t sz = pkt->data.frame.sz;
    WebdartcVp8Output *out = malloc(sizeof(*out) + sz);
    if (!out) return NULL;
    out->size = sz;
    out->pts_us = (int64_t)pkt->data.frame.pts;
    out->is_keyframe = (pkt->data.frame.flags & VPX_FRAME_IS_KEY) ? 1 : 0;
    memcpy(output_payload(out), pkt->data.frame.buf, sz);
    return out;
  }
}

const uint8_t *webdartc_vp8_output_data(WebdartcVp8Output *out) {
  return out ? output_payload(out) : NULL;
}

size_t webdartc_vp8_output_size(WebdartcVp8Output *out) {
  return out ? out->size : 0;
}

int64_t webdartc_vp8_output_pts_us(WebdartcVp8Output *out) {
  return out ? out->pts_us : 0;
}

int webdartc_vp8_output_is_keyframe(WebdartcVp8Output *out) {
  return out ? out->is_keyframe : 0;
}

void webdartc_vp8_output_free(WebdartcVp8Output *out) {
  free(out);
}

const char *webdartc_vp8_get_version_string(void) {
  return vpx_codec_version_str();
}

// ── Decoder ───────────────────────────────────────────────────────────

struct WebdartcVp8Decoder {
  vpx_codec_ctx_t ctx;
  vpx_codec_iter_t drain_iter;
  int64_t last_pts_us;
  int initialized;
};

// Holds a contiguous I420 copy of one decoded frame so the Dart side
// only crosses the FFI boundary once per drain.
struct WebdartcVp8Frame {
  int width;
  int height;
  int64_t pts_us;
  // Followed by width*height*3/2 bytes of I420 data (Y then U then V).
};

static inline uint8_t *frame_payload(WebdartcVp8Frame *f) {
  return (uint8_t *)(f + 1);
}

WebdartcVp8Decoder *webdartc_vp8_decoder_create(void) {
  WebdartcVp8Decoder *dec = calloc(1, sizeof(*dec));
  if (!dec) return NULL;
  if (vpx_codec_dec_init_ver(&dec->ctx, vpx_codec_vp8_dx(), NULL, 0,
                             VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
    free(dec);
    return NULL;
  }
  dec->initialized = 1;
  return dec;
}

void webdartc_vp8_decoder_destroy(WebdartcVp8Decoder *dec) {
  if (!dec) return;
  if (dec->initialized) {
    vpx_codec_destroy(&dec->ctx);
  }
  free(dec);
}

int webdartc_vp8_decoder_decode(
    WebdartcVp8Decoder *dec,
    const uint8_t *data, size_t size, int64_t pts_us) {
  if (!dec) return VPX_CODEC_INVALID_PARAM;
  dec->drain_iter = NULL;
  // Stash the caller's PTS. libvpx returns it as `vpx_image_t.user_priv`
  // when we pass it through `vpx_codec_decode`'s 4th arg, but tunnelling
  // a 64-bit value through a void* is ugly on 32-bit hosts — instead
  // assume the caller decodes one frame at a time and threads PTS
  // separately, which is true for our RTP-driven pipeline.
  dec->last_pts_us = pts_us;
  return (int)vpx_codec_decode(
      &dec->ctx, data, (unsigned int)size, NULL, 0 /* deadline ignored */);
}

WebdartcVp8Frame *webdartc_vp8_decoder_drain_one(WebdartcVp8Decoder *dec) {
  if (!dec) return NULL;
  vpx_image_t *img = vpx_codec_get_frame(&dec->ctx, &dec->drain_iter);
  if (!img) return NULL;
  if (img->fmt != VPX_IMG_FMT_I420) {
    // Caller asked for VP8 which is always I420; defensive only.
    return NULL;
  }

  const int w = (int)img->d_w;
  const int h = (int)img->d_h;
  // I420 UV planes round half-dimensions UP (RFC 4587 / ITU-T H.262
  // §6.1.1.4). Matters only for odd width/height, but VP9 dynamic
  // resolution change can deliver them.
  const int uv_w = (w + 1) >> 1;
  const int uv_h = (h + 1) >> 1;
  const size_t y_size = (size_t)w * (size_t)h;
  const size_t uv_size = (size_t)uv_w * (size_t)uv_h;
  const size_t total = y_size + 2 * uv_size;

  WebdartcVp8Frame *f = malloc(sizeof(*f) + total);
  if (!f) return NULL;
  f->width = w;
  f->height = h;
  f->pts_us = dec->last_pts_us;

  // libvpx aligns plane strides to 16/32; when stride equals plane
  // width (typical at 320, 640, 1280…) one memcpy beats a row loop.
  uint8_t *dst = frame_payload(f);
  dst = copy_plane(dst, img->planes[VPX_PLANE_Y],
                   img->stride[VPX_PLANE_Y], w, h);
  dst = copy_plane(dst, img->planes[VPX_PLANE_U],
                   img->stride[VPX_PLANE_U], uv_w, uv_h);
  copy_plane(dst, img->planes[VPX_PLANE_V],
             img->stride[VPX_PLANE_V], uv_w, uv_h);
  return f;
}

const uint8_t *webdartc_vp8_frame_data(WebdartcVp8Frame *f) {
  return f ? frame_payload(f) : NULL;
}

int webdartc_vp8_frame_width(WebdartcVp8Frame *f) {
  return f ? f->width : 0;
}

int webdartc_vp8_frame_height(WebdartcVp8Frame *f) {
  return f ? f->height : 0;
}

int64_t webdartc_vp8_frame_pts_us(WebdartcVp8Frame *f) {
  return f ? f->pts_us : 0;
}

void webdartc_vp8_frame_free(WebdartcVp8Frame *f) {
  free(f);
}
