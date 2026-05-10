#include "webdartc_vp9.h"

#include <stdlib.h>
#include <string.h>

#include <vpx/vpx_encoder.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>

// ── Encoder ───────────────────────────────────────────────────────────

struct WebdartcVp9Encoder {
  vpx_codec_ctx_t ctx;
  vpx_image_t img;
  vpx_codec_iter_t drain_iter;
  int initialized;
};

struct WebdartcVp9Output {
  size_t size;
  int64_t pts_us;
  int is_keyframe;
  // Followed by `size` bytes of encoded data.
};

static inline uint8_t *output_payload(WebdartcVp9Output *out) {
  return (uint8_t *)(out + 1);
}

WebdartcVp9Encoder *webdartc_vp9_encoder_create(
    int width, int height, int target_bitrate_kbps, int kf_max_dist) {
  WebdartcVp9Encoder *enc = calloc(1, sizeof(*enc));
  if (!enc) return NULL;

  vpx_codec_enc_cfg_t cfg;
  vpx_codec_iface_t *iface = vpx_codec_vp9_cx();
  if (vpx_codec_enc_config_default(iface, &cfg, 0) != VPX_CODEC_OK) {
    free(enc);
    return NULL;
  }
  cfg.g_w = (unsigned int)width;
  cfg.g_h = (unsigned int)height;
  cfg.g_timebase.num = 1;
  cfg.g_timebase.den = 1000000;
  cfg.rc_target_bitrate = (unsigned int)target_bitrate_kbps;
  cfg.g_error_resilient = 1;
  cfg.kf_max_dist = (unsigned int)kf_max_dist;
  // VP9 defaults to multi-pass with `g_lag_in_frames = 25` and alt-ref
  // buffering, so `vpx_codec_encode` queues frames internally and emits
  // nothing for the first few calls. Force single-pass real-time with no
  // lookahead so each encode() produces one drainable packet.
  cfg.g_pass = VPX_RC_ONE_PASS;
  cfg.g_lag_in_frames = 0;

  if (vpx_codec_enc_init_ver(
          &enc->ctx, iface, &cfg, 0, VPX_ENCODER_ABI_VERSION) !=
      VPX_CODEC_OK) {
    free(enc);
    return NULL;
  }
  // VP9 defaults `cpu-used` to 0 (slowest, best quality), which is
  // order-of-magnitude too slow for live encoding. libwebrtc uses 5–7
  // for camera RTC; 6 is a good middle. Cyclic-refresh AQ mode is the
  // standard pick for screencast/RTC because it amortises keyframe
  // cost across multiple inter frames.
  vpx_codec_control(&enc->ctx, VP8E_SET_CPUUSED, 6);
  vpx_codec_control(&enc->ctx, VP9E_SET_AQ_MODE, 3);
  enc->initialized = 1;
  return enc;
}

void webdartc_vp9_encoder_destroy(WebdartcVp9Encoder *enc) {
  if (!enc) return;
  if (enc->initialized) {
    vpx_codec_destroy(&enc->ctx);
  }
  free(enc);
}

int webdartc_vp9_encoder_encode(
    WebdartcVp9Encoder *enc,
    const uint8_t *y, const uint8_t *u, const uint8_t *v,
    int width, int height, int64_t pts_us, int force_keyframe) {
  if (!enc) return VPX_CODEC_INVALID_PARAM;

  vpx_img_wrap(&enc->img, VPX_IMG_FMT_I420, width, height, 1, (uint8_t *)y);
  enc->img.planes[VPX_PLANE_Y] = (uint8_t *)y;
  enc->img.planes[VPX_PLANE_U] = (uint8_t *)u;
  enc->img.planes[VPX_PLANE_V] = (uint8_t *)v;
  enc->img.stride[VPX_PLANE_Y] = width;
  enc->img.stride[VPX_PLANE_U] = width >> 1;
  enc->img.stride[VPX_PLANE_V] = width >> 1;

  enc->drain_iter = NULL;
  const int flags = force_keyframe ? VPX_EFLAG_FORCE_KF : 0;
  return (int)vpx_codec_encode(
      &enc->ctx, &enc->img, pts_us, 1, flags, VPX_DL_REALTIME);
}

WebdartcVp9Output *webdartc_vp9_encoder_drain_one(WebdartcVp9Encoder *enc) {
  if (!enc) return NULL;
  while (1) {
    const vpx_codec_cx_pkt_t *pkt =
        vpx_codec_get_cx_data(&enc->ctx, &enc->drain_iter);
    if (!pkt) return NULL;
    if (pkt->kind != VPX_CODEC_CX_FRAME_PKT) continue;

    const size_t sz = pkt->data.frame.sz;
    WebdartcVp9Output *out = malloc(sizeof(*out) + sz);
    if (!out) return NULL;
    out->size = sz;
    out->pts_us = (int64_t)pkt->data.frame.pts;
    out->is_keyframe = (pkt->data.frame.flags & VPX_FRAME_IS_KEY) ? 1 : 0;
    memcpy(output_payload(out), pkt->data.frame.buf, sz);
    return out;
  }
}

const uint8_t *webdartc_vp9_output_data(WebdartcVp9Output *out) {
  return out ? output_payload(out) : NULL;
}

size_t webdartc_vp9_output_size(WebdartcVp9Output *out) {
  return out ? out->size : 0;
}

int64_t webdartc_vp9_output_pts_us(WebdartcVp9Output *out) {
  return out ? out->pts_us : 0;
}

int webdartc_vp9_output_is_keyframe(WebdartcVp9Output *out) {
  return out ? out->is_keyframe : 0;
}

void webdartc_vp9_output_free(WebdartcVp9Output *out) {
  free(out);
}

const char *webdartc_vp9_get_version_string(void) {
  return vpx_codec_version_str();
}

// ── Decoder ───────────────────────────────────────────────────────────

struct WebdartcVp9Decoder {
  vpx_codec_ctx_t ctx;
  vpx_codec_iter_t drain_iter;
  int64_t last_pts_us;
  int initialized;
};

struct WebdartcVp9Frame {
  int width;
  int height;
  int64_t pts_us;
  // Followed by width*height*3/2 bytes of contiguous I420.
};

static inline uint8_t *frame_payload(WebdartcVp9Frame *f) {
  return (uint8_t *)(f + 1);
}

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

WebdartcVp9Decoder *webdartc_vp9_decoder_create(void) {
  WebdartcVp9Decoder *dec = calloc(1, sizeof(*dec));
  if (!dec) return NULL;
  if (vpx_codec_dec_init_ver(&dec->ctx, vpx_codec_vp9_dx(), NULL, 0,
                             VPX_DECODER_ABI_VERSION) != VPX_CODEC_OK) {
    free(dec);
    return NULL;
  }
  dec->initialized = 1;
  return dec;
}

void webdartc_vp9_decoder_destroy(WebdartcVp9Decoder *dec) {
  if (!dec) return;
  if (dec->initialized) {
    vpx_codec_destroy(&dec->ctx);
  }
  free(dec);
}

int webdartc_vp9_decoder_decode(
    WebdartcVp9Decoder *dec,
    const uint8_t *data, size_t size, int64_t pts_us) {
  if (!dec) return VPX_CODEC_INVALID_PARAM;
  dec->drain_iter = NULL;
  dec->last_pts_us = pts_us;
  return (int)vpx_codec_decode(
      &dec->ctx, data, (unsigned int)size, NULL, 0);
}

WebdartcVp9Frame *webdartc_vp9_decoder_drain_one(WebdartcVp9Decoder *dec) {
  if (!dec) return NULL;
  vpx_image_t *img = vpx_codec_get_frame(&dec->ctx, &dec->drain_iter);
  if (!img) return NULL;
  if (img->fmt != VPX_IMG_FMT_I420) return NULL;

  const int w = (int)img->d_w;
  const int h = (int)img->d_h;
  // I420 UV planes round half-dimensions UP. Matters for odd
  // width/height — VP9 dynamic-resolution streams can hit this.
  const int uv_w = (w + 1) >> 1;
  const int uv_h = (h + 1) >> 1;
  const size_t y_size = (size_t)w * (size_t)h;
  const size_t uv_size = (size_t)uv_w * (size_t)uv_h;
  const size_t total = y_size + 2 * uv_size;

  WebdartcVp9Frame *f = malloc(sizeof(*f) + total);
  if (!f) return NULL;
  f->width = w;
  f->height = h;
  f->pts_us = dec->last_pts_us;

  uint8_t *dst = frame_payload(f);
  dst = copy_plane(dst, img->planes[VPX_PLANE_Y],
                   img->stride[VPX_PLANE_Y], w, h);
  dst = copy_plane(dst, img->planes[VPX_PLANE_U],
                   img->stride[VPX_PLANE_U], uv_w, uv_h);
  copy_plane(dst, img->planes[VPX_PLANE_V],
             img->stride[VPX_PLANE_V], uv_w, uv_h);
  return f;
}

const uint8_t *webdartc_vp9_frame_data(WebdartcVp9Frame *f) {
  return f ? frame_payload(f) : NULL;
}

int webdartc_vp9_frame_width(WebdartcVp9Frame *f) {
  return f ? f->width : 0;
}

int webdartc_vp9_frame_height(WebdartcVp9Frame *f) {
  return f ? f->height : 0;
}

int64_t webdartc_vp9_frame_pts_us(WebdartcVp9Frame *f) {
  return f ? f->pts_us : 0;
}

void webdartc_vp9_frame_free(WebdartcVp9Frame *f) {
  free(f);
}
