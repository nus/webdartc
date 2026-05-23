// AVFoundation + CoreAudio + AudioToolbox media I/O shim. See wmd_media.h
// for the C API shape. ARC is enabled (build hook passes -fobjc-arc).

#import "wmd_media.h"

#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <CoreAudio/CoreAudio.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <pthread.h>
#import <stdlib.h>
#import <string.h>

// ── Authorization ─────────────────────────────────────────────────────────

static int wmd_request_access_blocking(AVMediaType type) {
  AVAuthorizationStatus status =
      [AVCaptureDevice authorizationStatusForMediaType:type];
  if (status == AVAuthorizationStatusAuthorized) return 1;
  if (status == AVAuthorizationStatusDenied ||
      status == AVAuthorizationStatusRestricted) return 0;

  __block BOOL granted = NO;
  dispatch_semaphore_t sem = dispatch_semaphore_create(0);
  [AVCaptureDevice requestAccessForMediaType:type
                           completionHandler:^(BOOL g) {
    granted = g;
    dispatch_semaphore_signal(sem);
  }];
  dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
  return granted ? 1 : 0;
}

int wmd_request_video_access_blocking(void) {
  return wmd_request_access_blocking(AVMediaTypeVideo);
}

int wmd_request_audio_access_blocking(void) {
  return wmd_request_access_blocking(AVMediaTypeAudio);
}

// ── Device enumeration ────────────────────────────────────────────────────

struct WmdDeviceList {
  int count;
  char** ids;
  char** names;
};

static char* dup_cstr(NSString* s) {
  const char* utf8 = [s UTF8String];
  size_t n = strlen(utf8) + 1;
  char* out = (char*)malloc(n);
  if (!out) return NULL;
  memcpy(out, utf8, n);
  return out;
}

// `[AVCaptureDevice devicesWithMediaType:]` is formally deprecated on
// macOS 10.15 but remains the only one-liner that works uniformly for
// both video and audio across all macOS versions we target.
// `AVCaptureDeviceDiscoverySession` requires per-platform deviceTypes
// arrays (microphone enum lives in different SDKs on macOS / iOS), and
// rolling that out for marginal gain isn't worth the ifdef churn.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static NSArray<AVCaptureDevice*>* list_devices(AVMediaType type) {
  return [AVCaptureDevice devicesWithMediaType:type];
}
#pragma clang diagnostic pop

static AVCaptureDevice* find_device(const char* device_id, AVMediaType type) {
  if (device_id && device_id[0]) {
    AVCaptureDevice* d = [AVCaptureDevice
        deviceWithUniqueID:[NSString stringWithUTF8String:device_id]];
    if (d) return d;
  }
  return [AVCaptureDevice defaultDeviceWithMediaType:type];
}

// Returns 1 iff the CoreAudio device has at least one output stream.
static int coreaudio_device_has_output(AudioDeviceID dev) {
  AudioObjectPropertyAddress addr = {
    kAudioDevicePropertyStreams,
    kAudioObjectPropertyScopeOutput,
    kAudioObjectPropertyElementMain,
  };
  UInt32 size = 0;
  OSStatus s = AudioObjectGetPropertyDataSize(dev, &addr, 0, NULL, &size);
  if (s != noErr) return 0;
  return size > 0 ? 1 : 0;
}

// CoreAudio CFStringRef property → C string. Caller frees with free().
static char* coreaudio_device_string(AudioDeviceID dev,
                                     AudioObjectPropertySelector sel) {
  AudioObjectPropertyAddress addr = {
    sel,
    kAudioObjectPropertyScopeGlobal,
    kAudioObjectPropertyElementMain,
  };
  CFStringRef cf = NULL;
  UInt32 size = sizeof(cf);
  OSStatus s = AudioObjectGetPropertyData(dev, &addr, 0, NULL, &size, &cf);
  if (s != noErr || !cf) return NULL;
  CFIndex len = CFStringGetMaximumSizeForEncoding(
      CFStringGetLength(cf), kCFStringEncodingUTF8) + 1;
  char* buf = (char*)malloc((size_t)len);
  if (!buf || !CFStringGetCString(cf, buf, len, kCFStringEncodingUTF8)) {
    free(buf);
    CFRelease(cf);
    return NULL;
  }
  CFRelease(cf);
  return buf;
}

static WmdDeviceList* enumerate_audio_outputs(void) {
  WmdDeviceList* list = (WmdDeviceList*)calloc(1, sizeof(WmdDeviceList));
  if (!list) return NULL;

  AudioObjectPropertyAddress addr = {
    kAudioHardwarePropertyDevices,
    kAudioObjectPropertyScopeGlobal,
    kAudioObjectPropertyElementMain,
  };
  UInt32 size = 0;
  if (AudioObjectGetPropertyDataSize(
          kAudioObjectSystemObject, &addr, 0, NULL, &size) != noErr) {
    return list;
  }
  int total = (int)(size / sizeof(AudioDeviceID));
  if (total <= 0) return list;

  AudioDeviceID* devs = (AudioDeviceID*)malloc(size);
  if (!devs) return list;
  if (AudioObjectGetPropertyData(
          kAudioObjectSystemObject, &addr, 0, NULL, &size, devs) != noErr) {
    free(devs);
    return list;
  }

  // Worst case every device has an output; tighten later.
  list->ids = (char**)calloc(total, sizeof(char*));
  list->names = (char**)calloc(total, sizeof(char*));
  int n = 0;
  for (int i = 0; i < total; ++i) {
    if (!coreaudio_device_has_output(devs[i])) continue;
    char* uid = coreaudio_device_string(devs[i], kAudioDevicePropertyDeviceUID);
    char* name = coreaudio_device_string(devs[i], kAudioObjectPropertyName);
    if (!uid || !name) {
      free(uid);
      free(name);
      continue;
    }
    list->ids[n] = uid;
    list->names[n] = name;
    n++;
  }
  list->count = n;
  free(devs);
  return list;
}

WmdDeviceList* wmd_devices_enumerate(int kind) {
  if (kind == 2) return enumerate_audio_outputs();
  AVMediaType type = (kind == 0) ? AVMediaTypeVideo : AVMediaTypeAudio;
  NSArray<AVCaptureDevice*>* devices = list_devices(type);
  WmdDeviceList* list = (WmdDeviceList*)calloc(1, sizeof(WmdDeviceList));
  if (!list) return NULL;
  list->count = (int)devices.count;
  if (list->count == 0) return list;
  list->ids = (char**)calloc(list->count, sizeof(char*));
  list->names = (char**)calloc(list->count, sizeof(char*));
  for (int i = 0; i < list->count; ++i) {
    list->ids[i] = dup_cstr(devices[i].uniqueID);
    list->names[i] = dup_cstr(devices[i].localizedName);
  }
  return list;
}

int wmd_devices_count(WmdDeviceList* list) {
  return list ? list->count : 0;
}

const char* wmd_devices_id(WmdDeviceList* list, int idx) {
  if (!list || idx < 0 || idx >= list->count) return NULL;
  return list->ids[idx];
}

const char* wmd_devices_name(WmdDeviceList* list, int idx) {
  if (!list || idx < 0 || idx >= list->count) return NULL;
  return list->names[idx];
}

void wmd_devices_free(WmdDeviceList* list) {
  if (!list) return;
  for (int i = 0; i < list->count; ++i) {
    free(list->ids[i]);
    free(list->names[i]);
  }
  free(list->ids);
  free(list->names);
  free(list);
}

// ── Video capture ─────────────────────────────────────────────────────────

// Layout-critical: `frame` MUST be the first member so a `WmdVideoFrame*`
// returned to Dart aliases the node pointer. Lets `wmd_video_frame_free`
// free the whole node with one `free()` and skips a per-frame node malloc
// in the delegate callback.
typedef struct WmdVideoFrameNode {
  WmdVideoFrame frame;
  struct WmdVideoFrameNode* next;
} WmdVideoFrameNode;

@class WmdVideoDelegate;

struct WmdVideoCapture {
  AVCaptureSession* session;
  AVCaptureDeviceInput* input;
  AVCaptureVideoDataOutput* output;
  dispatch_queue_t queue;
  WmdVideoDelegate* delegate;
  pthread_mutex_t mu;
  WmdVideoFrameNode* head;
  WmdVideoFrameNode* tail;
  int qcount;
  int qmax;
  CFAbsoluteTime t0;
  BOOL t0_set;
};

@interface WmdVideoDelegate
    : NSObject <AVCaptureVideoDataOutputSampleBufferDelegate>
@property(nonatomic) WmdVideoCapture* owner;
@end

// Called with mu held. Drops the oldest frame once qcount exceeds qmax so
// memory is bounded if Dart stops draining.
static void video_enqueue_locked(WmdVideoCapture* cap, WmdVideoFrameNode* n) {
  if (cap->tail) cap->tail->next = n;
  else cap->head = n;
  cap->tail = n;
  cap->qcount++;
  while (cap->qcount > cap->qmax && cap->head) {
    WmdVideoFrameNode* drop = cap->head;
    cap->head = drop->next;
    if (!cap->head) cap->tail = NULL;
    cap->qcount--;
    wmd_video_frame_free(&drop->frame);
  }
}

static WmdVideoFrameNode* nv12_to_i420_node(CVPixelBufferRef pb,
                                            int64_t pts_us) {
  CVPixelBufferLockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
  size_t w = CVPixelBufferGetWidth(pb);
  size_t h = CVPixelBufferGetHeight(pb);
  size_t yStride = CVPixelBufferGetBytesPerRowOfPlane(pb, 0);
  size_t uvStride = CVPixelBufferGetBytesPerRowOfPlane(pb, 1);
  const uint8_t* yPlane =
      (const uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 0);
  const uint8_t* uvPlane =
      (const uint8_t*)CVPixelBufferGetBaseAddressOfPlane(pb, 1);

  size_t uvW = w / 2;
  size_t uvH = h / 2;
  size_t ySize = w * h;
  size_t uvSize = uvW * uvH;
  size_t total = ySize + 2 * uvSize;

  WmdVideoFrameNode* n =
      (WmdVideoFrameNode*)malloc(sizeof(WmdVideoFrameNode));
  if (!n) {
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    return NULL;
  }
  uint8_t* data = (uint8_t*)malloc(total);
  if (!data) {
    free(n);
    CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
    return NULL;
  }
  n->frame.data = data;
  n->frame.size = (int32_t)total;
  n->frame.width = (int32_t)w;
  n->frame.height = (int32_t)h;
  n->frame.pts_us = pts_us;
  n->next = NULL;

  // Y plane: stride may exceed width.
  for (size_t r = 0; r < h; ++r) {
    memcpy(data + r * w, yPlane + r * yStride, w);
  }
  // NV12 UV plane → separate U and V planes (I420).
  uint8_t* uOut = data + ySize;
  uint8_t* vOut = uOut + uvSize;
  for (size_t r = 0; r < uvH; ++r) {
    const uint8_t* src = uvPlane + r * uvStride;
    uint8_t* du = uOut + r * uvW;
    uint8_t* dv = vOut + r * uvW;
    for (size_t c = 0; c < uvW; ++c) {
      du[c] = src[2 * c];
      dv[c] = src[2 * c + 1];
    }
  }
  CVPixelBufferUnlockBaseAddress(pb, kCVPixelBufferLock_ReadOnly);
  return n;
}

@implementation WmdVideoDelegate
- (void)captureOutput:(AVCaptureOutput*)output
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
           fromConnection:(AVCaptureConnection*)connection {
  (void)output;
  (void)connection;
  WmdVideoCapture* cap = self.owner;
  if (!cap) return;
  CVImageBufferRef img = CMSampleBufferGetImageBuffer(sampleBuffer);
  if (!img) return;

  // CMSampleBuffer's PTS is wall-clock or device-uptime depending on
  // source; translate to session-relative microseconds using the first
  // frame as t=0 so downstream encoders see a monotonic clock starting
  // near zero.
  CMTime pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer);
  double tsec = (CMTIME_IS_VALID(pts) && pts.timescale > 0)
      ? ((double)pts.value / (double)pts.timescale)
      : CFAbsoluteTimeGetCurrent();
  pthread_mutex_lock(&cap->mu);
  if (!cap->t0_set) {
    cap->t0 = tsec;
    cap->t0_set = YES;
  }
  int64_t pts_us = (int64_t)((tsec - cap->t0) * 1e6);
  pthread_mutex_unlock(&cap->mu);

  WmdVideoFrameNode* n = nv12_to_i420_node(img, pts_us);
  if (!n) return;
  pthread_mutex_lock(&cap->mu);
  video_enqueue_locked(cap, n);
  pthread_mutex_unlock(&cap->mu);
}
@end

// Pick the smallest activeFormat that fits the requested fps and is at
// least the requested resolution; AVCaptureVideoDataOutput downscales to
// the exact requested width/height via kCVPixelBufferWidth/HeightKey.
static void configure_video_format(AVCaptureDevice* dev, int width, int height,
                                   double fps) {
  AVCaptureDeviceFormat* best = nil;
  long bestDelta = LONG_MAX;
  for (AVCaptureDeviceFormat* f in dev.formats) {
    CMVideoDimensions d =
        CMVideoFormatDescriptionGetDimensions(f.formatDescription);
    if (d.width < width || d.height < height) continue;
    BOOL fpsOk = NO;
    for (AVFrameRateRange* r in f.videoSupportedFrameRateRanges) {
      if (r.minFrameRate <= fps && fps <= r.maxFrameRate) {
        fpsOk = YES;
        break;
      }
    }
    if (!fpsOk) continue;
    long delta = (long)((d.width - width) + (d.height - height));
    if (delta < bestDelta) {
      bestDelta = delta;
      best = f;
    }
  }
  if (!best) return;
  NSError* err = nil;
  if (![dev lockForConfiguration:&err]) return;
  dev.activeFormat = best;
  CMTime frameDur = CMTimeMake(1, (int32_t)fps);
  dev.activeVideoMinFrameDuration = frameDur;
  dev.activeVideoMaxFrameDuration = frameDur;
  [dev unlockForConfiguration];
}

WmdVideoCapture* wmd_video_capture_create(const char* device_id, int width,
                                          int height, double fps) {
  @autoreleasepool {
    AVCaptureDevice* dev = find_device(device_id, AVMediaTypeVideo);
    if (!dev) return NULL;
    NSError* err = nil;
    AVCaptureDeviceInput* input =
        [AVCaptureDeviceInput deviceInputWithDevice:dev error:&err];
    if (!input) return NULL;

    AVCaptureSession* session = [[AVCaptureSession alloc] init];
    if (![session canAddInput:input]) return NULL;
    [session addInput:input];

    if (width > 0 && height > 0 && fps > 0) {
      configure_video_format(dev, width, height, fps);
    }

    AVCaptureVideoDataOutput* output =
        [[AVCaptureVideoDataOutput alloc] init];
    output.alwaysDiscardsLateVideoFrames = YES;
    // macOS honours kCVPixelBufferWidth/HeightKey by downscaling the
    // device's native frame; iOS ignores them (active format dimensions
    // are delivered as-is there).
    NSMutableDictionary* settings = [@{
      (NSString*)kCVPixelBufferPixelFormatTypeKey :
          @(kCVPixelFormatType_420YpCbCr8BiPlanarFullRange),
    } mutableCopy];
    if (width > 0) settings[(NSString*)kCVPixelBufferWidthKey] = @(width);
    if (height > 0) settings[(NSString*)kCVPixelBufferHeightKey] = @(height);
    output.videoSettings = settings;

    WmdVideoCapture* cap =
        (WmdVideoCapture*)calloc(1, sizeof(WmdVideoCapture));
    if (!cap) return NULL;
    pthread_mutex_init(&cap->mu, NULL);
    cap->qmax = 4;
    cap->session = session;
    cap->input = input;
    cap->output = output;
    cap->queue =
        dispatch_queue_create("webdartc.wmd.video", DISPATCH_QUEUE_SERIAL);

    WmdVideoDelegate* delegate = [[WmdVideoDelegate alloc] init];
    delegate.owner = cap;
    cap->delegate = delegate;
    [output setSampleBufferDelegate:delegate queue:cap->queue];
    if (![session canAddOutput:output]) {
      pthread_mutex_destroy(&cap->mu);
      free(cap);
      return NULL;
    }
    [session addOutput:output];
    return cap;
  }
}

int wmd_video_capture_start(WmdVideoCapture* cap) {
  if (!cap) return 0;
  [cap->session startRunning];
  return cap->session.isRunning ? 1 : 0;
}

void wmd_video_capture_stop(WmdVideoCapture* cap) {
  if (!cap) return;
  [cap->session stopRunning];
}

void wmd_video_capture_release(WmdVideoCapture* cap) {
  if (!cap) return;
  [cap->session stopRunning];
  cap->delegate.owner = NULL;
  [cap->output setSampleBufferDelegate:nil queue:NULL];
  // Fence any delegate callback already in flight on the serial queue
  // before destroying the mutex. Without this, a callback that entered
  // the @interface method body before setSampleBufferDelegate:nil could
  // still try to lock `mu` after pthread_mutex_destroy ran → UB.
  if (cap->queue) {
    dispatch_sync(cap->queue, ^{});
  }
  pthread_mutex_lock(&cap->mu);
  WmdVideoFrameNode* p = cap->head;
  while (p) {
    WmdVideoFrameNode* nx = p->next;
    wmd_video_frame_free(&p->frame);
    p = nx;
  }
  cap->head = NULL;
  cap->tail = NULL;
  cap->qcount = 0;
  pthread_mutex_unlock(&cap->mu);
  pthread_mutex_destroy(&cap->mu);
  cap->session = nil;
  cap->input = nil;
  cap->output = nil;
  cap->delegate = nil;
  cap->queue = NULL;
  free(cap);
}

WmdVideoFrame* wmd_video_capture_pop(WmdVideoCapture* cap) {
  if (!cap) return NULL;
  pthread_mutex_lock(&cap->mu);
  WmdVideoFrameNode* n = cap->head;
  if (n) {
    cap->head = n->next;
    if (!cap->head) cap->tail = NULL;
    cap->qcount--;
  }
  pthread_mutex_unlock(&cap->mu);
  return n ? &n->frame : NULL;
}

void wmd_video_capture_set_max_queue(WmdVideoCapture* cap, int n) {
  if (!cap || n < 1) return;
  pthread_mutex_lock(&cap->mu);
  cap->qmax = n;
  pthread_mutex_unlock(&cap->mu);
}

void wmd_video_frame_free(WmdVideoFrame* frame) {
  if (!frame) return;
  free(frame->data);
  // `frame` aliases its containing WmdVideoFrameNode (frame is the first
  // member) — this free() releases the whole node.
  free(frame);
}

// ── Audio capture ─────────────────────────────────────────────────────────

typedef struct WmdAudioFrameNode {
  WmdAudioFrame frame;
  struct WmdAudioFrameNode* next;
} WmdAudioFrameNode;

@class WmdAudioDelegate;

struct WmdAudioCapture {
  AVCaptureSession* session;
  AVCaptureDeviceInput* input;
  AVCaptureAudioDataOutput* output;
  dispatch_queue_t queue;
  WmdAudioDelegate* delegate;
  pthread_mutex_t mu;
  WmdAudioFrameNode* head;
  WmdAudioFrameNode* tail;
  int qcount;
  int qmax;
  int sample_rate;
  int channels;
  CFAbsoluteTime t0;
  BOOL t0_set;
};

@interface WmdAudioDelegate
    : NSObject <AVCaptureAudioDataOutputSampleBufferDelegate>
@property(nonatomic) WmdAudioCapture* owner;
@end

static void audio_enqueue_locked(WmdAudioCapture* cap, WmdAudioFrameNode* n) {
  if (cap->tail) cap->tail->next = n;
  else cap->head = n;
  cap->tail = n;
  cap->qcount++;
  while (cap->qcount > cap->qmax && cap->head) {
    WmdAudioFrameNode* drop = cap->head;
    cap->head = drop->next;
    if (!cap->head) cap->tail = NULL;
    cap->qcount--;
    wmd_audio_frame_free(&drop->frame);
  }
}

// AVCaptureAudioDataOutput's `audioSettings` is honoured on macOS so the
// fast path is hit there; iOS ignores it and delivers device-native (often
// f32 non-interleaved). The branches normalise both into s16 interleaved
// before reaching Dart so callers don't need to handle multiple shapes.
static WmdAudioFrameNode* extract_audio_node(CMSampleBufferRef sb,
                                             int64_t pts_us) {
  CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sb);
  if (!fmt) return NULL;
  const AudioStreamBasicDescription* asbd =
      CMAudioFormatDescriptionGetStreamBasicDescription(fmt);
  if (!asbd) return NULL;
  CMItemCount nFrames = CMSampleBufferGetNumSamples(sb);
  if (nFrames <= 0) return NULL;
  int channels = (int)asbd->mChannelsPerFrame;
  if (channels <= 0) return NULL;

  AudioBufferList abl;
  CMBlockBufferRef bb = NULL;
  OSStatus s = CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(
      sb, NULL, &abl, sizeof(abl),
      kCFAllocatorDefault, kCFAllocatorDefault, 0, &bb);
  if (s != noErr) return NULL;

  size_t outBytes = (size_t)nFrames * channels * 2;
  WmdAudioFrameNode* n =
      (WmdAudioFrameNode*)malloc(sizeof(WmdAudioFrameNode));
  uint8_t* outData = (uint8_t*)malloc(outBytes);
  if (!n || !outData) {
    free(n);
    free(outData);
    if (bb) CFRelease(bb);
    return NULL;
  }
  n->frame.data = outData;
  n->frame.size = (int32_t)outBytes;
  n->frame.sample_rate = (int32_t)asbd->mSampleRate;
  n->frame.channels = channels;
  n->frame.num_frames = (int32_t)nFrames;
  n->frame.pts_us = pts_us;
  n->next = NULL;

  const BOOL isFloat =
      (asbd->mFormatFlags & kAudioFormatFlagIsFloat) != 0;
  const BOOL isNonInterleaved =
      (asbd->mFormatFlags & kAudioFormatFlagIsNonInterleaved) != 0;

  if (!isFloat && !isNonInterleaved && asbd->mBitsPerChannel == 16) {
    const uint8_t* src = (const uint8_t*)abl.mBuffers[0].mData;
    size_t srcLen = abl.mBuffers[0].mDataByteSize;
    memcpy(outData, src, srcLen < outBytes ? srcLen : outBytes);
  } else if (isFloat && isNonInterleaved && asbd->mBitsPerChannel == 32) {
    int16_t* dst = (int16_t*)outData;
    for (CMItemCount i = 0; i < nFrames; ++i) {
      for (int ch = 0; ch < channels; ++ch) {
        const float* src = (const float*)abl.mBuffers[ch].mData;
        float v = src[i];
        if (v > 1.0f) v = 1.0f;
        if (v < -1.0f) v = -1.0f;
        dst[i * channels + ch] = (int16_t)(v * 32767.0f);
      }
    }
  } else if (isFloat && !isNonInterleaved && asbd->mBitsPerChannel == 32) {
    const float* src = (const float*)abl.mBuffers[0].mData;
    int16_t* dst = (int16_t*)outData;
    size_t total = (size_t)nFrames * channels;
    for (size_t i = 0; i < total; ++i) {
      float v = src[i];
      if (v > 1.0f) v = 1.0f;
      if (v < -1.0f) v = -1.0f;
      dst[i] = (int16_t)(v * 32767.0f);
    }
  } else {
    // Unsupported format combination — emit silence so downstream timing
    // is preserved rather than crashing.
    memset(outData, 0, outBytes);
  }
  if (bb) CFRelease(bb);
  return n;
}

@implementation WmdAudioDelegate
- (void)captureOutput:(AVCaptureOutput*)output
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
           fromConnection:(AVCaptureConnection*)connection {
  (void)output;
  (void)connection;
  WmdAudioCapture* cap = self.owner;
  if (!cap) return;
  CMTime pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer);
  double tsec = (CMTIME_IS_VALID(pts) && pts.timescale > 0)
      ? ((double)pts.value / (double)pts.timescale)
      : CFAbsoluteTimeGetCurrent();
  pthread_mutex_lock(&cap->mu);
  if (!cap->t0_set) {
    cap->t0 = tsec;
    cap->t0_set = YES;
  }
  int64_t pts_us = (int64_t)((tsec - cap->t0) * 1e6);
  pthread_mutex_unlock(&cap->mu);

  WmdAudioFrameNode* n = extract_audio_node(sampleBuffer, pts_us);
  if (!n) return;
  pthread_mutex_lock(&cap->mu);
  audio_enqueue_locked(cap, n);
  pthread_mutex_unlock(&cap->mu);
}
@end

WmdAudioCapture* wmd_audio_capture_create(const char* device_id,
                                          int sample_rate, int channels) {
  @autoreleasepool {
    AVCaptureDevice* dev = find_device(device_id, AVMediaTypeAudio);
    if (!dev) return NULL;
    NSError* err = nil;
    AVCaptureDeviceInput* input =
        [AVCaptureDeviceInput deviceInputWithDevice:dev error:&err];
    if (!input) return NULL;

    AVCaptureSession* session = [[AVCaptureSession alloc] init];
    if (![session canAddInput:input]) return NULL;
    [session addInput:input];

    AVCaptureAudioDataOutput* output =
        [[AVCaptureAudioDataOutput alloc] init];
    if (sample_rate > 0 && channels > 0) {
      output.audioSettings = @{
        (NSString*)AVFormatIDKey : @(kAudioFormatLinearPCM),
        (NSString*)AVSampleRateKey : @(sample_rate),
        (NSString*)AVNumberOfChannelsKey : @(channels),
        (NSString*)AVLinearPCMBitDepthKey : @(16),
        (NSString*)AVLinearPCMIsFloatKey : @NO,
        (NSString*)AVLinearPCMIsBigEndianKey : @NO,
        (NSString*)AVLinearPCMIsNonInterleaved : @NO,
      };
    }

    WmdAudioCapture* cap =
        (WmdAudioCapture*)calloc(1, sizeof(WmdAudioCapture));
    if (!cap) return NULL;
    pthread_mutex_init(&cap->mu, NULL);
    // 8 packets ≈ 80 ms at the typical 10 ms PCM buffer cadence — enough
    // headroom for jitter without unbounded latency on a stalled consumer.
    cap->qmax = 8;
    cap->session = session;
    cap->input = input;
    cap->output = output;
    cap->sample_rate = sample_rate;
    cap->channels = channels;
    cap->queue =
        dispatch_queue_create("webdartc.wmd.audio", DISPATCH_QUEUE_SERIAL);

    WmdAudioDelegate* delegate = [[WmdAudioDelegate alloc] init];
    delegate.owner = cap;
    cap->delegate = delegate;
    [output setSampleBufferDelegate:delegate queue:cap->queue];
    if (![session canAddOutput:output]) {
      pthread_mutex_destroy(&cap->mu);
      free(cap);
      return NULL;
    }
    [session addOutput:output];
    return cap;
  }
}

int wmd_audio_capture_start(WmdAudioCapture* cap) {
  if (!cap) return 0;
  [cap->session startRunning];
  return cap->session.isRunning ? 1 : 0;
}

void wmd_audio_capture_stop(WmdAudioCapture* cap) {
  if (!cap) return;
  [cap->session stopRunning];
}

void wmd_audio_capture_release(WmdAudioCapture* cap) {
  if (!cap) return;
  [cap->session stopRunning];
  cap->delegate.owner = NULL;
  [cap->output setSampleBufferDelegate:nil queue:NULL];
  if (cap->queue) {
    dispatch_sync(cap->queue, ^{});
  }
  pthread_mutex_lock(&cap->mu);
  WmdAudioFrameNode* p = cap->head;
  while (p) {
    WmdAudioFrameNode* nx = p->next;
    wmd_audio_frame_free(&p->frame);
    p = nx;
  }
  cap->head = NULL;
  cap->tail = NULL;
  cap->qcount = 0;
  pthread_mutex_unlock(&cap->mu);
  pthread_mutex_destroy(&cap->mu);
  cap->session = nil;
  cap->input = nil;
  cap->output = nil;
  cap->delegate = nil;
  cap->queue = NULL;
  free(cap);
}

WmdAudioFrame* wmd_audio_capture_pop(WmdAudioCapture* cap) {
  if (!cap) return NULL;
  pthread_mutex_lock(&cap->mu);
  WmdAudioFrameNode* n = cap->head;
  if (n) {
    cap->head = n->next;
    if (!cap->head) cap->tail = NULL;
    cap->qcount--;
  }
  pthread_mutex_unlock(&cap->mu);
  return n ? &n->frame : NULL;
}

void wmd_audio_capture_set_max_queue(WmdAudioCapture* cap, int n) {
  if (!cap || n < 1) return;
  pthread_mutex_lock(&cap->mu);
  cap->qmax = n;
  pthread_mutex_unlock(&cap->mu);
}

void wmd_audio_frame_free(WmdAudioFrame* frame) {
  if (!frame) return;
  free(frame->data);
  free(frame);
}

// ── Audio renderer ───────────────────────────────────────────────────────

// Pushed PCM chunk awaiting consumption by the AudioQueue callback.
// `data` is a flexible array member so header + samples take one
// allocation (matches WmdVideoFrameNode / WmdAudioFrameNode).
typedef struct WmdRenderChunk {
  int size;
  int consumed;
  struct WmdRenderChunk* next;
  uint8_t data[];
} WmdRenderChunk;

// Three back-to-back buffers of 20 ms each: enough for AudioQueue to keep
// the device fed across a single late push without underrunning, while
// keeping the worst-case device → first sample latency at ~60 ms.
#define WMD_RENDER_BUF_COUNT 3
#define WMD_RENDER_BUF_MS 20

struct WmdAudioRenderer {
  AudioQueueRef queue;
  AudioQueueBufferRef buffers[WMD_RENDER_BUF_COUNT];
  int buffer_bytes;
  int sample_rate;
  int channels;
  pthread_mutex_t mu;
  WmdRenderChunk* head;
  WmdRenderChunk* tail;
  int buffered_bytes;
  int max_buffered;
  bool started;
};

// AudioQueue's output callback. Runs on the queue's internal worker
// thread. Drains pushed chunks into `buf`; pads any remainder with
// silence so the device keeps playing during underruns.
static void render_cb(void* user, AudioQueueRef q, AudioQueueBufferRef buf) {
  (void)q;
  WmdAudioRenderer* r = (WmdAudioRenderer*)user;
  uint8_t* dst = (uint8_t*)buf->mAudioData;
  int remaining = r->buffer_bytes;

  pthread_mutex_lock(&r->mu);
  while (remaining > 0 && r->head) {
    WmdRenderChunk* c = r->head;
    int avail = c->size - c->consumed;
    int take = avail < remaining ? avail : remaining;
    memcpy(dst, c->data + c->consumed, (size_t)take);
    dst += take;
    remaining -= take;
    c->consumed += take;
    r->buffered_bytes -= take;
    if (c->consumed >= c->size) {
      r->head = c->next;
      if (!r->head) r->tail = NULL;
      free(c);
    }
  }
  pthread_mutex_unlock(&r->mu);

  if (remaining > 0) {
    memset(dst, 0, (size_t)remaining);
  }
  buf->mAudioDataByteSize = (UInt32)r->buffer_bytes;
  AudioQueueEnqueueBuffer(q, buf, 0, NULL);
}

WmdAudioRenderer* wmd_audio_renderer_create(int sample_rate, int channels) {
  if (sample_rate <= 0 || channels <= 0) return NULL;

  AudioStreamBasicDescription asbd = {0};
  asbd.mSampleRate = sample_rate;
  asbd.mFormatID = kAudioFormatLinearPCM;
  asbd.mFormatFlags =
      kLinearPCMFormatFlagIsSignedInteger | kLinearPCMFormatFlagIsPacked;
  asbd.mBitsPerChannel = 16;
  asbd.mChannelsPerFrame = (UInt32)channels;
  asbd.mFramesPerPacket = 1;
  asbd.mBytesPerFrame = (UInt32)(channels * 2);
  asbd.mBytesPerPacket = (UInt32)(channels * 2);

  WmdAudioRenderer* r =
      (WmdAudioRenderer*)calloc(1, sizeof(WmdAudioRenderer));
  if (!r) return NULL;
  pthread_mutex_init(&r->mu, NULL);
  r->sample_rate = sample_rate;
  r->channels = channels;
  r->buffer_bytes =
      (sample_rate * channels * 2 * WMD_RENDER_BUF_MS) / 1000;
  // 100 ms worth of buffered audio is the cap. Beyond that we drop the
  // oldest pushed chunks so memory stays bounded if the caller pushes
  // faster than playback consumes.
  r->max_buffered = (sample_rate * channels * 2 * 100) / 1000;

  OSStatus s = AudioQueueNewOutput(
      &asbd, render_cb, r, NULL, NULL, 0, &r->queue);
  if (s != noErr) {
    pthread_mutex_destroy(&r->mu);
    free(r);
    return NULL;
  }
  for (int i = 0; i < WMD_RENDER_BUF_COUNT; ++i) {
    s = AudioQueueAllocateBuffer(
        r->queue, (UInt32)r->buffer_bytes, &r->buffers[i]);
    if (s != noErr) {
      AudioQueueDispose(r->queue, true);
      pthread_mutex_destroy(&r->mu);
      free(r);
      return NULL;
    }
  }
  return r;
}

int wmd_audio_renderer_set_sink(WmdAudioRenderer* r, const char* device_id) {
  if (!r) return 0;
  if (!device_id || !device_id[0]) {
    // Restore default by clearing the property to an empty CFString.
    CFStringRef empty = CFSTR("");
    OSStatus s = AudioQueueSetProperty(
        r->queue, kAudioQueueProperty_CurrentDevice, &empty, sizeof(empty));
    return s == noErr ? 1 : 0;
  }
  CFStringRef uid = CFStringCreateWithCString(
      kCFAllocatorDefault, device_id, kCFStringEncodingUTF8);
  if (!uid) return 0;
  OSStatus s = AudioQueueSetProperty(
      r->queue, kAudioQueueProperty_CurrentDevice, &uid, sizeof(uid));
  CFRelease(uid);
  return s == noErr ? 1 : 0;
}

int wmd_audio_renderer_start(WmdAudioRenderer* r) {
  if (!r || r->started) return r ? 1 : 0;
  // Prime each AudioQueueBuffer with silence and enqueue so AudioQueue
  // has something to play immediately; subsequent refills come from the
  // callback.
  for (int i = 0; i < WMD_RENDER_BUF_COUNT; ++i) {
    AudioQueueBufferRef buf = r->buffers[i];
    memset(buf->mAudioData, 0, (size_t)r->buffer_bytes);
    buf->mAudioDataByteSize = (UInt32)r->buffer_bytes;
    AudioQueueEnqueueBuffer(r->queue, buf, 0, NULL);
  }
  OSStatus s = AudioQueueStart(r->queue, NULL);
  if (s != noErr) return 0;
  r->started = true;
  return 1;
}

void wmd_audio_renderer_stop(WmdAudioRenderer* r) {
  if (!r || !r->started) return;
  AudioQueueStop(r->queue, true);
  r->started = false;
}

void wmd_audio_renderer_release(WmdAudioRenderer* r) {
  if (!r) return;
  if (r->started) AudioQueueStop(r->queue, true);
  // `true` here also frees the AudioQueueBuffers and runs the callback's
  // teardown fence — no separate buffer dispose needed.
  AudioQueueDispose(r->queue, true);
  pthread_mutex_lock(&r->mu);
  WmdRenderChunk* c = r->head;
  while (c) {
    WmdRenderChunk* nx = c->next;
    free(c);
    c = nx;
  }
  pthread_mutex_unlock(&r->mu);
  pthread_mutex_destroy(&r->mu);
  free(r);
}

int wmd_audio_renderer_push(WmdAudioRenderer* r, const uint8_t* pcm_s16,
                            int num_bytes) {
  if (!r || !pcm_s16 || num_bytes <= 0) return 0;
  WmdRenderChunk* c =
      (WmdRenderChunk*)malloc(sizeof(WmdRenderChunk) + (size_t)num_bytes);
  if (!c) return 0;
  c->size = num_bytes;
  c->consumed = 0;
  c->next = NULL;
  memcpy(c->data, pcm_s16, (size_t)num_bytes);

  pthread_mutex_lock(&r->mu);
  if (r->tail) r->tail->next = c;
  else r->head = c;
  r->tail = c;
  r->buffered_bytes += num_bytes;
  // Drop oldest chunks until buffered_bytes is back under max — keeps
  // memory bounded if a stalled consumer + fast producer drift apart.
  while (r->buffered_bytes > r->max_buffered && r->head && r->head != r->tail) {
    WmdRenderChunk* drop = r->head;
    r->head = drop->next;
    r->buffered_bytes -= (drop->size - drop->consumed);
    free(drop);
  }
  pthread_mutex_unlock(&r->mu);
  return num_bytes;
}

void wmd_audio_renderer_set_max_buffered(WmdAudioRenderer* r, int bytes) {
  if (!r || bytes < 0) return;
  pthread_mutex_lock(&r->mu);
  r->max_buffered = bytes;
  pthread_mutex_unlock(&r->mu);
}
