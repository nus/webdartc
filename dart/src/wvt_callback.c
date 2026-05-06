#include "wvt_callback.h"

#include <stdlib.h>

// ── Encoder ────────────────────────────────────────────────────────────────

void wvt_enc_queue_init(WvtEncQueue* q) {
  pthread_mutex_init(&q->mu, NULL);
  q->head = NULL;
  q->tail = NULL;
}

WvtEncQueue* wvt_enc_queue_create(void) {
  WvtEncQueue* q = (WvtEncQueue*)malloc(sizeof(WvtEncQueue));
  if (!q) return NULL;
  wvt_enc_queue_init(q);
  return q;
}

void wvt_enc_queue_release(WvtEncQueue* q) {
  if (!q) return;
  wvt_enc_queue_destroy(q);
  free(q);
}

void wvt_enc_callback(void* output_ref_con,
                      void* source_ref_con,
                      OSStatus status,
                      VTEncodeInfoFlags info_flags,
                      CMSampleBufferRef sample_buffer) {
  WvtEncQueue* q = (WvtEncQueue*)output_ref_con;
  WvtEncNode* n = (WvtEncNode*)malloc(sizeof(WvtEncNode));
  if (!n) return;
  if (sample_buffer) CFRetain(sample_buffer);
  n->sb = sample_buffer;
  // PTS is passed as the source_ref_con pointer's integer value (no
  // separate malloc'd box); see vt_helper.dart for the matching encode.
  n->pts_us = (int64_t)(intptr_t)source_ref_con;
  n->status = status;
  n->info_flags = (int32_t)info_flags;
  n->next = NULL;
  pthread_mutex_lock(&q->mu);
  if (q->tail) q->tail->next = n;
  else q->head = n;
  q->tail = n;
  pthread_mutex_unlock(&q->mu);
}

WvtEncNode* wvt_enc_queue_pop(WvtEncQueue* q) {
  pthread_mutex_lock(&q->mu);
  WvtEncNode* n = q->head;
  if (n) {
    q->head = n->next;
    if (!q->head) q->tail = NULL;
    n->next = NULL;
  }
  pthread_mutex_unlock(&q->mu);
  return n;
}

void wvt_enc_node_free(WvtEncNode* n) {
  if (!n) return;
  if (n->sb) CFRelease(n->sb);
  free(n);
}

void wvt_enc_queue_destroy(WvtEncQueue* q) {
  pthread_mutex_lock(&q->mu);
  WvtEncNode* p = q->head;
  while (p) {
    WvtEncNode* next = p->next;
    if (p->sb) CFRelease(p->sb);
    free(p);
    p = next;
  }
  q->head = NULL;
  q->tail = NULL;
  pthread_mutex_unlock(&q->mu);
  pthread_mutex_destroy(&q->mu);
}

// ── Decoder ────────────────────────────────────────────────────────────────

void wvt_dec_queue_init(WvtDecQueue* q) {
  pthread_mutex_init(&q->mu, NULL);
  q->head = NULL;
  q->tail = NULL;
}

WvtDecQueue* wvt_dec_queue_create(void) {
  WvtDecQueue* q = (WvtDecQueue*)malloc(sizeof(WvtDecQueue));
  if (!q) return NULL;
  wvt_dec_queue_init(q);
  return q;
}

void wvt_dec_queue_release(WvtDecQueue* q) {
  if (!q) return;
  wvt_dec_queue_destroy(q);
  free(q);
}

void wvt_dec_callback(void* output_ref_con,
                      void* source_ref_con,
                      OSStatus status,
                      VTDecodeInfoFlags info_flags,
                      CVImageBufferRef image_buffer,
                      CMTime presentation_ts,
                      CMTime presentation_dur) {
  (void)presentation_ts;
  (void)presentation_dur;
  WvtDecQueue* q = (WvtDecQueue*)output_ref_con;
  WvtDecNode* n = (WvtDecNode*)malloc(sizeof(WvtDecNode));
  if (!n) return;
  if (image_buffer) CFRetain(image_buffer);
  n->img = image_buffer;
  // PTS-as-pointer trick — see encoder callback above.
  n->pts_us = (int64_t)(intptr_t)source_ref_con;
  n->status = status;
  n->info_flags = (int32_t)info_flags;
  n->next = NULL;
  pthread_mutex_lock(&q->mu);
  if (q->tail) q->tail->next = n;
  else q->head = n;
  q->tail = n;
  pthread_mutex_unlock(&q->mu);
}

WvtDecNode* wvt_dec_queue_pop(WvtDecQueue* q) {
  pthread_mutex_lock(&q->mu);
  WvtDecNode* n = q->head;
  if (n) {
    q->head = n->next;
    if (!q->head) q->tail = NULL;
    n->next = NULL;
  }
  pthread_mutex_unlock(&q->mu);
  return n;
}

void wvt_dec_node_free(WvtDecNode* n) {
  if (!n) return;
  if (n->img) CFRelease(n->img);
  free(n);
}

void wvt_dec_queue_destroy(WvtDecQueue* q) {
  pthread_mutex_lock(&q->mu);
  WvtDecNode* p = q->head;
  while (p) {
    WvtDecNode* next = p->next;
    if (p->img) CFRelease(p->img);
    free(p);
    p = next;
  }
  q->head = NULL;
  q->tail = NULL;
  pthread_mutex_unlock(&q->mu);
  pthread_mutex_destroy(&q->mu);
}
