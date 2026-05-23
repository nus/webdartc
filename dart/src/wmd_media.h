// macOS / iOS media I/O shim.
//
// Wraps AVFoundation (camera + microphone capture), CoreAudio HAL (output
// device enumeration), and AudioToolbox AudioQueue (speaker playback)
// behind a flat C ABI so Dart can drive each one without going through
// ObjC runtime calls. The shim owns:
//
//   - AVCaptureSession + inputs/outputs setup
//   - The serial dispatch queue that receives delegate callbacks
//   - A pthread-mutex-protected FIFO queue per session
//   - NV12 → I420 conversion on the dequeue path (video)
//   - The AudioQueue + ring buffer for output playback
//
// All other logic (device enumeration result handling, MediaStreamTrack
// wiring, polling, lifecycle) lives in Dart. Same overall layout as the
// VideoToolbox helper shim (`wvt_callback.h`): the C side handles the
// threading-sensitive portion, Dart pulls bytes off a queue on the
// isolate thread.

#ifndef WEBDARTC_WMD_MEDIA_H
#define WEBDARTC_WMD_MEDIA_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(_WIN32)
#define WMD_EXPORT __declspec(dllexport)
#else
#define WMD_EXPORT __attribute__((visibility("default")))
#endif

// ── Authorization ─────────────────────────────────────────────────────────
//
// On macOS 10.14+ and all iOS, accessing the camera / microphone requires
// TCC permission. Returns 1 if access is granted, 0 otherwise. Both calls
// block the caller's thread on the first invocation (until the user
// dismisses the system prompt) — subsequent calls return immediately.

WMD_EXPORT int wmd_request_video_access_blocking(void);
WMD_EXPORT int wmd_request_audio_access_blocking(void);

// ── Device enumeration ────────────────────────────────────────────────────

typedef struct WmdDeviceList WmdDeviceList;

// kind: 0 = video input (AVFoundation), 1 = audio input (AVFoundation),
// 2 = audio output (CoreAudio HAL). Returns NULL on failure.
WMD_EXPORT WmdDeviceList* wmd_devices_enumerate(int kind);
WMD_EXPORT int wmd_devices_count(WmdDeviceList* list);

// Returned pointers are owned by `list` and remain valid until
// `wmd_devices_free`. Indices outside [0, count) return NULL.
WMD_EXPORT const char* wmd_devices_id(WmdDeviceList* list, int idx);
WMD_EXPORT const char* wmd_devices_name(WmdDeviceList* list, int idx);
WMD_EXPORT void wmd_devices_free(WmdDeviceList* list);

// ── Video capture ─────────────────────────────────────────────────────────

typedef struct WmdVideoCapture WmdVideoCapture;

// One I420 frame popped from the capture queue. `data` is malloc'd; free
// the whole struct (including data) with `wmd_video_frame_free`.
typedef struct WmdVideoFrame {
  uint8_t* data;     // Y plane, then U plane, then V plane (I420).
  int32_t size;     // width*height + 2 * (width/2)*(height/2)
  int32_t width;
  int32_t height;
  int64_t pts_us;   // Presentation timestamp in microseconds.
} WmdVideoFrame;

// device_id may be NULL — picks the system default video device.
// width/height/fps are hints; the OS chooses the closest supported format.
// Returns NULL on failure.
WMD_EXPORT WmdVideoCapture* wmd_video_capture_create(
    const char* device_id, int width, int height, double fps);

// Returns 1 on success, 0 on failure.
WMD_EXPORT int wmd_video_capture_start(WmdVideoCapture* cap);
WMD_EXPORT void wmd_video_capture_stop(WmdVideoCapture* cap);
WMD_EXPORT void wmd_video_capture_release(WmdVideoCapture* cap);

// FIFO pop. Returns NULL if no frame is queued. Frames buffer in the C
// queue while Dart isn't draining; `wmd_video_capture_set_max_queue`
// caps the buffered count (default 4) and silently drops the oldest
// frame when the cap is hit, to keep memory bounded if the consumer
// stalls.
WMD_EXPORT WmdVideoFrame* wmd_video_capture_pop(WmdVideoCapture* cap);
WMD_EXPORT void wmd_video_capture_set_max_queue(WmdVideoCapture* cap, int n);
WMD_EXPORT void wmd_video_frame_free(WmdVideoFrame* frame);

// ── Audio capture ─────────────────────────────────────────────────────────

typedef struct WmdAudioCapture WmdAudioCapture;

// One PCM s16-interleaved audio frame. Memory ownership matches
// `WmdVideoFrame`: `data` is malloc'd inside the struct allocation,
// free with `wmd_audio_frame_free`.
typedef struct WmdAudioFrame {
  uint8_t* data;        // s16 interleaved, channels * num_frames samples.
  int32_t size;        // num_frames * channels * 2 bytes.
  int32_t sample_rate;
  int32_t channels;
  int32_t num_frames;
  int64_t pts_us;
} WmdAudioFrame;

// device_id may be NULL — picks the system default audio input device.
// sample_rate/channels are hints; on macOS AVCaptureAudioDataOutput honours
// `audioSettings` so the requested format is usually delivered as-is.
// Returns NULL on failure.
WMD_EXPORT WmdAudioCapture* wmd_audio_capture_create(
    const char* device_id, int sample_rate, int channels);

WMD_EXPORT int wmd_audio_capture_start(WmdAudioCapture* cap);
WMD_EXPORT void wmd_audio_capture_stop(WmdAudioCapture* cap);
WMD_EXPORT void wmd_audio_capture_release(WmdAudioCapture* cap);

WMD_EXPORT WmdAudioFrame* wmd_audio_capture_pop(WmdAudioCapture* cap);
WMD_EXPORT void wmd_audio_capture_set_max_queue(WmdAudioCapture* cap, int n);
WMD_EXPORT void wmd_audio_frame_free(WmdAudioFrame* frame);

// ── Audio renderer (speaker output) ───────────────────────────────────────
//
// AudioQueue-backed s16-interleaved PCM sink. Push samples from any
// thread; AudioQueue drives playback on its internal worker. The renderer
// holds an internal mutex-protected linked list of pushed chunks and a
// pool of AudioQueueBuffers that the callback refills with silence when
// the queue drains.

typedef struct WmdAudioRenderer WmdAudioRenderer;

// sample_rate / channels must match the format of subsequent pushes.
// Returns NULL on failure.
WMD_EXPORT WmdAudioRenderer* wmd_audio_renderer_create(int sample_rate,
                                                       int channels);

// Set the output device by CoreAudio UID (as returned by
// `wmd_devices_id` for kind=2). NULL → system default. Returns 1 on
// success, 0 if the device id isn't found.
WMD_EXPORT int wmd_audio_renderer_set_sink(WmdAudioRenderer* r,
                                           const char* device_id);

// Returns 1 if AudioQueue started, 0 otherwise.
WMD_EXPORT int wmd_audio_renderer_start(WmdAudioRenderer* r);
WMD_EXPORT void wmd_audio_renderer_stop(WmdAudioRenderer* r);
WMD_EXPORT void wmd_audio_renderer_release(WmdAudioRenderer* r);

// Append PCM s16-interleaved samples to the internal ring. Returns the
// number of bytes accepted (always equals `num_bytes` unless the ring is
// at its cap — see `wmd_audio_renderer_set_max_buffered`, default 100 ms
// at the configured rate, after which the oldest chunk is dropped).
WMD_EXPORT int wmd_audio_renderer_push(WmdAudioRenderer* r,
                                       const uint8_t* pcm_s16, int num_bytes);
WMD_EXPORT void wmd_audio_renderer_set_max_buffered(WmdAudioRenderer* r,
                                                    int bytes);

#if defined(__cplusplus)
}
#endif

#endif  // WEBDARTC_WMD_MEDIA_H
