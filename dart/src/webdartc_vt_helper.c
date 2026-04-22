// VideoToolbox H.264 encoder/decoder helper.
//
// Exists because VideoToolbox delivers output via a C callback on an
// internal worker thread; Dart FFI callbacks cannot synchronously CFRetain
// a CMSampleBuffer before the callback returns. This helper does the
// CFRetain + queue bookkeeping on the VT thread, then exposes a
// synchronous pull API to Dart.

#include "webdartc_vt_helper.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreVideo/CoreVideo.h>
#include <VideoToolbox/VideoToolbox.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ABI_VERSION 1

int32_t webdartc_vt_helper_abi_version(void) { return ABI_VERSION; }

// ── Encoder output queue ───────────────────────────────────────────────────

struct WvtEncoderOutput {
  uint8_t* data;  // Annex B bitstream, malloc'd
  int32_t size;
  int32_t is_keyframe;
  int64_t pts_us;
  WvtEncoderOutput* next;
};

struct WvtEncoder {
  VTCompressionSessionRef session;
  int32_t width;
  int32_t height;
  pthread_mutex_t mu;
  WvtEncoderOutput* head;
  WvtEncoderOutput* tail;
};

static void enc_enqueue(WvtEncoder* enc, WvtEncoderOutput* out) {
  pthread_mutex_lock(&enc->mu);
  out->next = NULL;
  if (enc->tail) enc->tail->next = out;
  else enc->head = out;
  enc->tail = out;
  pthread_mutex_unlock(&enc->mu);
}

// Convert a CMSampleBuffer (AVCC-format NALs) to Annex B, prepending SPS/PPS
// for keyframes. Returns 0 on success.
static int extract_annex_b(CMSampleBufferRef sb, uint8_t** out_data,
                           int32_t* out_size, int32_t* is_keyframe) {
  int is_key = 1;
  CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sb, false);
  if (attachments && CFArrayGetCount(attachments) > 0) {
    CFDictionaryRef dict =
        (CFDictionaryRef)CFArrayGetValueAtIndex(attachments, 0);
    if (CFDictionaryContainsKey(dict, kCMSampleAttachmentKey_NotSync)) {
      is_key = 0;
    }
  }
  *is_keyframe = is_key;

  CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sb);
  if (!block) return -1;

  size_t block_size = 0;
  char* block_ptr = NULL;
  OSStatus s = CMBlockBufferGetDataPointer(block, 0, NULL, &block_size, &block_ptr);
  if (s != noErr || !block_ptr) return -2;

  size_t total = 0;
  const uint8_t* sps_data = NULL;
  size_t sps_size = 0;
  const uint8_t* pps_data = NULL;
  size_t pps_size = 0;
  int nal_header_size = 4;

  if (is_key) {
    CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sb);
    size_t param_count = 0;
    int header_sz_out = 0;
    if (CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
            fmt, 0, NULL, NULL, &param_count, &header_sz_out) == noErr &&
        param_count >= 2) {
      nal_header_size = header_sz_out;
      CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, 0, &sps_data, &sps_size, NULL, NULL);
      CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, 1, &pps_data, &pps_size, NULL, NULL);
      total += 4 + sps_size + 4 + pps_size;
    }
  }

  // Sum AVCC NAL sizes.
  const uint8_t* in = (const uint8_t*)block_ptr;
  size_t pos = 0;
  while (pos + (size_t)nal_header_size <= block_size) {
    uint32_t nal_len = 0;
    for (int i = 0; i < nal_header_size; i++) {
      nal_len = (nal_len << 8) | in[pos + i];
    }
    total += 4 + nal_len;
    pos += nal_header_size + nal_len;
  }

  uint8_t* out = (uint8_t*)malloc(total);
  if (!out) return -3;
  size_t w = 0;
  if (sps_data) {
    out[w++] = 0; out[w++] = 0; out[w++] = 0; out[w++] = 1;
    memcpy(out + w, sps_data, sps_size); w += sps_size;
  }
  if (pps_data) {
    out[w++] = 0; out[w++] = 0; out[w++] = 0; out[w++] = 1;
    memcpy(out + w, pps_data, pps_size); w += pps_size;
  }
  pos = 0;
  while (pos + (size_t)nal_header_size <= block_size) {
    uint32_t nal_len = 0;
    for (int i = 0; i < nal_header_size; i++) {
      nal_len = (nal_len << 8) | in[pos + i];
    }
    out[w++] = 0; out[w++] = 0; out[w++] = 0; out[w++] = 1;
    memcpy(out + w, in + pos + nal_header_size, nal_len);
    w += nal_len;
    pos += nal_header_size + nal_len;
  }

  *out_data = out;
  *out_size = (int32_t)w;
  return 0;
}

static void enc_callback(void* output_ref_con, void* source_ref_con,
                         OSStatus status, VTEncodeInfoFlags info_flags,
                         CMSampleBufferRef sample_buffer) {
  WvtEncoder* enc = (WvtEncoder*)output_ref_con;
  int64_t pts_us = 0;
  if (source_ref_con) {
    pts_us = *(int64_t*)source_ref_con;
    free(source_ref_con);
  }
  if (status != noErr || !sample_buffer) return;
  if (info_flags & kVTEncodeInfo_FrameDropped) return;

  uint8_t* data = NULL;
  int32_t size = 0;
  int32_t is_key = 0;
  if (extract_annex_b(sample_buffer, &data, &size, &is_key) != 0) return;

  WvtEncoderOutput* out = (WvtEncoderOutput*)malloc(sizeof(WvtEncoderOutput));
  out->data = data;
  out->size = size;
  out->is_keyframe = is_key;
  out->pts_us = pts_us;
  enc_enqueue(enc, out);
}

static void enc_set_int(VTCompressionSessionRef s, CFStringRef key, int32_t v) {
  CFNumberRef num = CFNumberCreate(NULL, kCFNumberSInt32Type, &v);
  VTSessionSetProperty(s, key, num);
  CFRelease(num);
}

WvtEncoder* wvt_encoder_create(int32_t width, int32_t height, int32_t bitrate,
                               int32_t fps, int32_t keyframe_interval) {
  WvtEncoder* enc = (WvtEncoder*)calloc(1, sizeof(WvtEncoder));
  enc->width = width;
  enc->height = height;
  pthread_mutex_init(&enc->mu, NULL);

  OSStatus s = VTCompressionSessionCreate(
      kCFAllocatorDefault, width, height, kCMVideoCodecType_H264,
      NULL, NULL, NULL, enc_callback, enc, &enc->session);
  if (s != noErr) {
    pthread_mutex_destroy(&enc->mu);
    free(enc);
    return NULL;
  }

  VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
  VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
  VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_ProfileLevel,
                       kVTProfileLevel_H264_Baseline_AutoLevel);
  enc_set_int(enc->session, kVTCompressionPropertyKey_AverageBitRate, bitrate);
  enc_set_int(enc->session, kVTCompressionPropertyKey_MaxKeyFrameInterval, keyframe_interval);
  enc_set_int(enc->session, kVTCompressionPropertyKey_ExpectedFrameRate, fps);

  VTCompressionSessionPrepareToEncodeFrames(enc->session);
  return enc;
}

static int upload_i420(CVPixelBufferRef buf, int w, int h,
                       const uint8_t* y, const uint8_t* u, const uint8_t* v,
                       int y_stride, int uv_stride) {
  if (CVPixelBufferLockBaseAddress(buf, 0) != kCVReturnSuccess) return -1;
  uint8_t* dst;
  size_t dst_stride;

  dst = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(buf, 0);
  dst_stride = CVPixelBufferGetBytesPerRowOfPlane(buf, 0);
  for (int r = 0; r < h; r++) memcpy(dst + r * dst_stride, y + r * y_stride, w);

  int uvw = w >> 1, uvh = h >> 1;
  dst = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(buf, 1);
  dst_stride = CVPixelBufferGetBytesPerRowOfPlane(buf, 1);
  for (int r = 0; r < uvh; r++) memcpy(dst + r * dst_stride, u + r * uv_stride, uvw);

  dst = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(buf, 2);
  dst_stride = CVPixelBufferGetBytesPerRowOfPlane(buf, 2);
  for (int r = 0; r < uvh; r++) memcpy(dst + r * dst_stride, v + r * uv_stride, uvw);

  CVPixelBufferUnlockBaseAddress(buf, 0);
  return 0;
}

int32_t wvt_encoder_encode(WvtEncoder* enc,
                           const uint8_t* y, const uint8_t* u, const uint8_t* v,
                           int32_t y_stride, int32_t uv_stride,
                           int64_t pts_us, int32_t force_keyframe) {
  if (!enc || !enc->session) return -1;

  CFDictionaryRef empty = CFDictionaryCreate(NULL, NULL, NULL, 0,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  const void* attr_keys[] = { kCVPixelBufferIOSurfacePropertiesKey };
  const void* attr_vals[] = { empty };
  CFDictionaryRef attrs = CFDictionaryCreate(NULL, attr_keys, attr_vals, 1,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFRelease(empty);

  CVPixelBufferRef pix = NULL;
  OSStatus s = CVPixelBufferCreate(
      kCFAllocatorDefault, enc->width, enc->height,
      kCVPixelFormatType_420YpCbCr8Planar, attrs, &pix);
  CFRelease(attrs);
  if (s != noErr || !pix) return -2;

  if (upload_i420(pix, enc->width, enc->height, y, u, v, y_stride, uv_stride) != 0) {
    CVPixelBufferRelease(pix);
    return -3;
  }

  CFDictionaryRef frame_props = NULL;
  if (force_keyframe) {
    const void* k = kVTEncodeFrameOptionKey_ForceKeyFrame;
    const void* vv = kCFBooleanTrue;
    frame_props = CFDictionaryCreate(NULL, &k, &vv, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  }

  int64_t* pts_copy = (int64_t*)malloc(sizeof(int64_t));
  *pts_copy = pts_us;

  CMTime pts = CMTimeMake(pts_us, 1000000);
  CMTime dur = kCMTimeInvalid;
  s = VTCompressionSessionEncodeFrame(enc->session, pix, pts, dur,
                                      frame_props, pts_copy, NULL);
  CVPixelBufferRelease(pix);
  if (frame_props) CFRelease(frame_props);
  if (s != noErr) { free(pts_copy); return -4; }

  // Synchronously complete so the queue is populated before return.
  VTCompressionSessionCompleteFrames(enc->session, kCMTimeInvalid);
  return 0;
}

WvtEncoderOutput* wvt_encoder_drain_one(WvtEncoder* enc) {
  if (!enc) return NULL;
  pthread_mutex_lock(&enc->mu);
  WvtEncoderOutput* out = enc->head;
  if (out) {
    enc->head = out->next;
    if (!enc->head) enc->tail = NULL;
    out->next = NULL;
  }
  pthread_mutex_unlock(&enc->mu);
  return out;
}

int32_t wvt_encoder_output_size(WvtEncoderOutput* out) { return out->size; }
int32_t wvt_encoder_output_is_keyframe(WvtEncoderOutput* out) { return out->is_keyframe; }
int64_t wvt_encoder_output_pts_us(WvtEncoderOutput* out) { return out->pts_us; }
const uint8_t* wvt_encoder_output_data(WvtEncoderOutput* out) { return out->data; }
void wvt_encoder_output_free(WvtEncoderOutput* out) {
  if (!out) return;
  if (out->data) free(out->data);
  free(out);
}

void wvt_encoder_destroy(WvtEncoder* enc) {
  if (!enc) return;
  if (enc->session) {
    VTCompressionSessionCompleteFrames(enc->session, kCMTimeInvalid);
    VTCompressionSessionInvalidate(enc->session);
    CFRelease(enc->session);
  }
  pthread_mutex_lock(&enc->mu);
  WvtEncoderOutput* p = enc->head;
  while (p) {
    WvtEncoderOutput* n = p->next;
    free(p->data);
    free(p);
    p = n;
  }
  pthread_mutex_unlock(&enc->mu);
  pthread_mutex_destroy(&enc->mu);
  free(enc);
}

// ── Decoder ───────────────────────────────────────────────────────────────

struct WvtDecodedFrame {
  uint8_t* data;  // packed I420, malloc'd
  int32_t size;
  int32_t width;
  int32_t height;
  int64_t pts_us;
  WvtDecodedFrame* next;
};

struct WvtDecoder {
  VTDecompressionSessionRef session;
  CMVideoFormatDescriptionRef fmt_desc;
  int32_t width;
  int32_t height;
  uint8_t* sps;
  int32_t sps_size;
  uint8_t* pps;
  int32_t pps_size;
  pthread_mutex_t mu;
  WvtDecodedFrame* head;
  WvtDecodedFrame* tail;
};

static void dec_enqueue(WvtDecoder* dec, WvtDecodedFrame* f) {
  pthread_mutex_lock(&dec->mu);
  f->next = NULL;
  if (dec->tail) dec->tail->next = f;
  else dec->head = f;
  dec->tail = f;
  pthread_mutex_unlock(&dec->mu);
}

static void dec_callback(void* output_ref_con, void* source_ref_con,
                         OSStatus status, VTDecodeInfoFlags info_flags,
                         CVImageBufferRef image_buffer, CMTime pts,
                         CMTime duration) {
  WvtDecoder* dec = (WvtDecoder*)output_ref_con;
  int64_t pts_us = 0;
  if (source_ref_con) {
    pts_us = *(int64_t*)source_ref_con;
    free(source_ref_con);
  }
  if (status != noErr || !image_buffer) return;
  if (info_flags & kVTDecodeInfo_FrameDropped) return;

  CVPixelBufferRef pb = image_buffer;
  if (CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly) != kCVReturnSuccess)
    return;

  OSType fmt = CVPixelBufferGetPixelFormatType(pb);
  if (fmt != kCVPixelFormatType_420YpCbCr8Planar &&
      fmt != kCVPixelFormatType_420YpCbCr8BiPlanarFullRange &&
      fmt != kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange) {
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    return;
  }

  int w = (int)CVPixelBufferGetWidth(pb);
  int h = (int)CVPixelBufferGetHeight(pb);
  int uvw = w >> 1;
  int uvh = h >> 1;
  int i420_size = w * h + uvw * uvh * 2;
  uint8_t* data = (uint8_t*)malloc(i420_size);
  if (!data) {
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    return;
  }

  if (fmt == kCVPixelFormatType_420YpCbCr8Planar) {
    uint8_t* sy = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    size_t sy_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    for (int r = 0; r < h; r++) memcpy(data + r * w, sy + r * sy_stride, w);
    uint8_t* su = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    size_t su_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
    for (int r = 0; r < uvh; r++)
      memcpy(data + w * h + r * uvw, su + r * su_stride, uvw);
    uint8_t* sv = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 2);
    size_t sv_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 2);
    for (int r = 0; r < uvh; r++)
      memcpy(data + w * h + uvw * uvh + r * uvw, sv + r * sv_stride, uvw);
  } else if (fmt == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange ||
             fmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange) {
    uint8_t* sy = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
    size_t sy_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
    for (int r = 0; r < h; r++) memcpy(data + r * w, sy + r * sy_stride, w);
    uint8_t* suv = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 1);
    size_t suv_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
    uint8_t* du = data + w * h;
    uint8_t* dv = du + uvw * uvh;
    for (int r = 0; r < uvh; r++) {
      const uint8_t* row = suv + r * suv_stride;
      for (int c = 0; c < uvw; c++) {
        du[r * uvw + c] = row[c * 2];
        dv[r * uvw + c] = row[c * 2 + 1];
      }
    }
  }
  CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);

  WvtDecodedFrame* f = (WvtDecodedFrame*)malloc(sizeof(WvtDecodedFrame));
  f->data = data;
  f->size = i420_size;
  f->width = w;
  f->height = h;
  f->pts_us = pts_us;
  dec_enqueue(dec, f);
}

WvtDecoder* wvt_decoder_create(void) {
  WvtDecoder* dec = (WvtDecoder*)calloc(1, sizeof(WvtDecoder));
  pthread_mutex_init(&dec->mu, NULL);
  return dec;
}

// Scan Annex B for the next start code. Returns offset or -1.
static int find_start_code(const uint8_t* buf, int buf_size, int start, int* sc_size) {
  for (int i = start; i + 2 < buf_size; i++) {
    if (buf[i] == 0 && buf[i + 1] == 0) {
      if (buf[i + 2] == 1) { *sc_size = 3; return i; }
      if (i + 3 < buf_size && buf[i + 2] == 0 && buf[i + 3] == 1) {
        *sc_size = 4; return i;
      }
    }
  }
  return -1;
}

static int setup_session(WvtDecoder* dec, const uint8_t* sps, int sps_size,
                         const uint8_t* pps, int pps_size) {
  if (dec->session) {
    VTDecompressionSessionInvalidate(dec->session);
    CFRelease(dec->session);
    dec->session = NULL;
  }
  if (dec->fmt_desc) { CFRelease(dec->fmt_desc); dec->fmt_desc = NULL; }

  const uint8_t* params[2] = { sps, pps };
  size_t sizes[2] = { (size_t)sps_size, (size_t)pps_size };
  OSStatus s = CMVideoFormatDescriptionCreateFromH264ParameterSets(
      kCFAllocatorDefault, 2, params, sizes, 4, &dec->fmt_desc);
  if (s != noErr) return -1;

  CMVideoDimensions dims = CMVideoFormatDescriptionGetDimensions(dec->fmt_desc);
  dec->width = dims.width;
  dec->height = dims.height;

  int32_t pf = kCVPixelFormatType_420YpCbCr8Planar;
  CFNumberRef pf_num = CFNumberCreate(NULL, kCFNumberSInt32Type, &pf);
  const void* k[] = { kCVPixelBufferPixelFormatTypeKey };
  const void* v[] = { pf_num };
  CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 1,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFRelease(pf_num);

  VTDecompressionOutputCallbackRecord cb = { dec_callback, dec };
  s = VTDecompressionSessionCreate(kCFAllocatorDefault, dec->fmt_desc, NULL,
                                   attrs, &cb, &dec->session);
  CFRelease(attrs);
  if (s != noErr) {
    CFRelease(dec->fmt_desc);
    dec->fmt_desc = NULL;
    return -2;
  }

  free(dec->sps); dec->sps = (uint8_t*)malloc(sps_size);
  memcpy(dec->sps, sps, sps_size); dec->sps_size = sps_size;
  free(dec->pps); dec->pps = (uint8_t*)malloc(pps_size);
  memcpy(dec->pps, pps, pps_size); dec->pps_size = pps_size;
  return 0;
}

int32_t wvt_decoder_decode(WvtDecoder* dec, const uint8_t* annex_b,
                           int32_t annex_b_size, int64_t pts_us) {
  if (!dec) return -1;

  // Split into NALs.
  int nal_off[64];
  int nal_sz[64];
  int nal_count = 0;
  int pos = 0;
  while (pos < annex_b_size && nal_count < 64) {
    int sc;
    int p = find_start_code(annex_b, annex_b_size, pos, &sc);
    if (p < 0) break;
    int nal_start = p + sc;
    int sc2;
    int p2 = find_start_code(annex_b, annex_b_size, nal_start, &sc2);
    int nal_end = (p2 < 0) ? annex_b_size : p2;
    nal_off[nal_count] = nal_start;
    nal_sz[nal_count] = nal_end - nal_start;
    nal_count++;
    pos = nal_end;
  }
  if (nal_count == 0) return -2;

  const uint8_t* sps = NULL; int sps_size = 0;
  const uint8_t* pps = NULL; int pps_size = 0;
  int slice_indices[64];
  int slice_count = 0;

  for (int i = 0; i < nal_count; i++) {
    int type = annex_b[nal_off[i]] & 0x1F;
    if (type == 7) { sps = annex_b + nal_off[i]; sps_size = nal_sz[i]; }
    else if (type == 8) { pps = annex_b + nal_off[i]; pps_size = nal_sz[i]; }
    else { slice_indices[slice_count++] = i; }
  }

  if (sps && pps) {
    int need_setup = !dec->session ||
                     sps_size != dec->sps_size ||
                     pps_size != dec->pps_size ||
                     memcmp(sps, dec->sps, sps_size) != 0 ||
                     memcmp(pps, dec->pps, pps_size) != 0;
    if (need_setup) {
      if (setup_session(dec, sps, sps_size, pps, pps_size) != 0) return -3;
    }
  }
  if (!dec->session) return -4;
  if (slice_count == 0) return 0;

  int32_t avcc_size = 0;
  for (int i = 0; i < slice_count; i++) avcc_size += 4 + nal_sz[slice_indices[i]];

  uint8_t* avcc = (uint8_t*)malloc(avcc_size);
  int w = 0;
  for (int i = 0; i < slice_count; i++) {
    int idx = slice_indices[i];
    uint32_t sz = (uint32_t)nal_sz[idx];
    avcc[w++] = (sz >> 24) & 0xFF;
    avcc[w++] = (sz >> 16) & 0xFF;
    avcc[w++] = (sz >> 8) & 0xFF;
    avcc[w++] = sz & 0xFF;
    memcpy(avcc + w, annex_b + nal_off[idx], sz);
    w += sz;
  }

  CMBlockBufferRef block = NULL;
  OSStatus s = CMBlockBufferCreateWithMemoryBlock(
      kCFAllocatorDefault, avcc, (size_t)avcc_size, kCFAllocatorMalloc,
      NULL, 0, (size_t)avcc_size, 0, &block);
  if (s != noErr) { free(avcc); return -5; }

  CMSampleTimingInfo timing = {
      .duration = kCMTimeInvalid,
      .presentationTimeStamp = CMTimeMake(pts_us, 1000000),
      .decodeTimeStamp = kCMTimeInvalid,
  };
  size_t sample_size = (size_t)avcc_size;
  CMSampleBufferRef sample = NULL;
  s = CMSampleBufferCreate(kCFAllocatorDefault, block, true, NULL, NULL,
                           dec->fmt_desc, 1, 1, &timing, 1, &sample_size, &sample);
  CFRelease(block);
  if (s != noErr) return -6;

  int64_t* pts_copy = (int64_t*)malloc(sizeof(int64_t));
  *pts_copy = pts_us;
  VTDecodeInfoFlags out_flags = 0;
  s = VTDecompressionSessionDecodeFrame(dec->session, sample, 0, pts_copy, &out_flags);
  CFRelease(sample);
  if (s != noErr) { free(pts_copy); return -7; }

  VTDecompressionSessionWaitForAsynchronousFrames(dec->session);
  return 0;
}

WvtDecodedFrame* wvt_decoder_drain_one(WvtDecoder* dec) {
  if (!dec) return NULL;
  pthread_mutex_lock(&dec->mu);
  WvtDecodedFrame* f = dec->head;
  if (f) {
    dec->head = f->next;
    if (!dec->head) dec->tail = NULL;
    f->next = NULL;
  }
  pthread_mutex_unlock(&dec->mu);
  return f;
}

int32_t wvt_decoded_frame_width(WvtDecodedFrame* f) { return f->width; }
int32_t wvt_decoded_frame_height(WvtDecodedFrame* f) { return f->height; }
int64_t wvt_decoded_frame_pts_us(WvtDecodedFrame* f) { return f->pts_us; }
int32_t wvt_decoded_frame_size(WvtDecodedFrame* f) { return f->size; }
const uint8_t* wvt_decoded_frame_data(WvtDecodedFrame* f) { return f->data; }
void wvt_decoded_frame_free(WvtDecodedFrame* f) {
  if (!f) return;
  if (f->data) free(f->data);
  free(f);
}

void wvt_decoder_destroy(WvtDecoder* dec) {
  if (!dec) return;
  if (dec->session) {
    VTDecompressionSessionInvalidate(dec->session);
    CFRelease(dec->session);
  }
  if (dec->fmt_desc) CFRelease(dec->fmt_desc);
  free(dec->sps); free(dec->pps);
  pthread_mutex_lock(&dec->mu);
  WvtDecodedFrame* p = dec->head;
  while (p) {
    WvtDecodedFrame* n = p->next;
    free(p->data);
    free(p);
    p = n;
  }
  pthread_mutex_unlock(&dec->mu);
  pthread_mutex_destroy(&dec->mu);
  free(dec);
}
