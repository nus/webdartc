// Minimal C shim that receives VideoToolbox compression/decompression
// callbacks from VT's worker threads, CFRetains the resulting buffer,
// and queues it for the Dart side to drain on the isolate thread.
//
// All other VT/CF/CV/CM logic (session create, encode/decode submit,
// Annex B / I420 extraction, teardown) lives in pure Dart and uses the
// ffigen-generated bindings — this file is only the threading-sensitive
// part that Dart's `NativeCallable.isolateGroupBound` cannot handle
// safely under realistic multi-stream patterns.

#ifndef WEBDARTC_WVT_CALLBACK_H
#define WEBDARTC_WVT_CALLBACK_H

#include <CoreMedia/CoreMedia.h>
#include <CoreVideo/CoreVideo.h>
#include <VideoToolbox/VideoToolbox.h>
#include <pthread.h>
#include <stdint.h>

#if _WIN32
#define WVT_EXPORT __declspec(dllexport)
#else
#define WVT_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ── Encoder ────────────────────────────────────────────────────────────────

typedef struct WvtEncNode {
  CMSampleBufferRef sb;        // CFRetained on enqueue, CFReleased on free.
  int64_t pts_us;
  int32_t status;
  int32_t info_flags;
  struct WvtEncNode* next;
} WvtEncNode;

typedef struct WvtEncQueue {
  pthread_mutex_t mu;
  WvtEncNode* head;
  WvtEncNode* tail;
} WvtEncQueue;

// Allocate + initialize an encoder queue. Returns NULL on alloc failure.
// Pair with `wvt_enc_queue_release` (which calls `wvt_enc_queue_destroy`
// internally). Allocating in C lets Dart treat the queue as opaque and
// avoids depending on pthread_mutex_t size.
WVT_EXPORT WvtEncQueue* wvt_enc_queue_create(void);

// Destroy + free a queue allocated via `wvt_enc_queue_create`.
WVT_EXPORT void wvt_enc_queue_release(WvtEncQueue* q);

// Initialize an encoder queue in-place (caller owns the storage). Most
// callers should use `wvt_enc_queue_create` instead.
WVT_EXPORT void wvt_enc_queue_init(WvtEncQueue* q);

// VT-compatible callback. Pass `&queue` as the output_ref_con when creating
// the VTCompressionSession; pass a malloc'd `int64_t*` PTS (in microseconds)
// as the source_ref_con when calling EncodeFrame (this function frees it).
WVT_EXPORT void wvt_enc_callback(
    void* output_ref_con,
    void* source_ref_con,
    OSStatus status,
    VTEncodeInfoFlags info_flags,
    CMSampleBufferRef sample_buffer);

// Pop one node from the queue (FIFO). Returns NULL if empty. Caller owns
// the returned node and must release it with `wvt_enc_node_free`.
WVT_EXPORT WvtEncNode* wvt_enc_queue_pop(WvtEncQueue* q);

WVT_EXPORT void wvt_enc_node_free(WvtEncNode* n);

// Drain and free any queued nodes, then destroy the mutex.
WVT_EXPORT void wvt_enc_queue_destroy(WvtEncQueue* q);

// ── Decoder ────────────────────────────────────────────────────────────────

typedef struct WvtDecNode {
  CVImageBufferRef img;        // CFRetained on enqueue, CFReleased on free.
  int64_t pts_us;
  int32_t status;
  int32_t info_flags;
  struct WvtDecNode* next;
} WvtDecNode;

typedef struct WvtDecQueue {
  pthread_mutex_t mu;
  WvtDecNode* head;
  WvtDecNode* tail;
} WvtDecQueue;

// See `wvt_enc_queue_create` for rationale.
WVT_EXPORT WvtDecQueue* wvt_dec_queue_create(void);
WVT_EXPORT void wvt_dec_queue_release(WvtDecQueue* q);
WVT_EXPORT void wvt_dec_queue_init(WvtDecQueue* q);

// VT-compatible callback. The `output_ref_con` should be `&queue`; the
// `source_ref_con` should be a malloc'd `int64_t*` PTS (this function frees
// it). The two CMTime arguments are ignored — Dart uses the queued PTS.
WVT_EXPORT void wvt_dec_callback(
    void* output_ref_con,
    void* source_ref_con,
    OSStatus status,
    VTDecodeInfoFlags info_flags,
    CVImageBufferRef image_buffer,
    CMTime presentation_ts,
    CMTime presentation_dur);

WVT_EXPORT WvtDecNode* wvt_dec_queue_pop(WvtDecQueue* q);
WVT_EXPORT void wvt_dec_node_free(WvtDecNode* n);
WVT_EXPORT void wvt_dec_queue_destroy(WvtDecQueue* q);

#ifdef __cplusplus
}
#endif

#endif  // WEBDARTC_WVT_CALLBACK_H
