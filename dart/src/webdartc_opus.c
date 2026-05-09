#include "webdartc_opus.h"
#include <opus.h>

WebdartcOpusEncoder *webdartc_opus_encoder_create(
    int32_t sample_rate, int channels, int application, int *error) {
  return (WebdartcOpusEncoder *)opus_encoder_create(
      sample_rate, channels, application, error);
}

void webdartc_opus_encoder_destroy(WebdartcOpusEncoder *st) {
  opus_encoder_destroy((OpusEncoder *)st);
}

int32_t webdartc_opus_encode(
    WebdartcOpusEncoder *st,
    const int16_t *pcm,
    int frame_size,
    unsigned char *data,
    int32_t max_data_bytes) {
  return opus_encode(
      (OpusEncoder *)st, pcm, frame_size, data, max_data_bytes);
}

int webdartc_opus_encoder_ctl_int(
    WebdartcOpusEncoder *st, int request, int32_t value) {
  return opus_encoder_ctl((OpusEncoder *)st, request, (opus_int32)value);
}

WebdartcOpusDecoder *webdartc_opus_decoder_create(
    int32_t sample_rate, int channels, int *error) {
  return (WebdartcOpusDecoder *)opus_decoder_create(
      sample_rate, channels, error);
}

void webdartc_opus_decoder_destroy(WebdartcOpusDecoder *st) {
  opus_decoder_destroy((OpusDecoder *)st);
}

int webdartc_opus_decode(
    WebdartcOpusDecoder *st,
    const unsigned char *data,
    int32_t len,
    int16_t *pcm,
    int frame_size,
    int decode_fec) {
  return opus_decode(
      (OpusDecoder *)st, data, len, pcm, frame_size, decode_fec);
}

const char *webdartc_opus_get_version_string(void) {
  return opus_get_version_string();
}
