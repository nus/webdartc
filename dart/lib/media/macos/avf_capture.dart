/// Pure-Dart bindings to the AVFoundation capture shim in
/// `src/wmd_capture.m`.
///
/// AVCaptureSession delegate callbacks run on AVFoundation's serial
/// queues — that foreign-thread work stays in C, where threading is
/// well-defined. Dart drains the resulting FIFO queue from the isolate
/// thread (see [NativeVideoCapture.popFrame] / [NativeAudioCapture.popFrame]).
/// Same pattern as `lib/codec/h264/videotoolbox/vt_helper.dart`.
@ffi.DefaultAsset('package:webdartc/media/macos/avf_capture.dart')
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

final class WmdDeviceList extends ffi.Opaque {}

final class WmdVideoCapture extends ffi.Opaque {}

final class WmdAudioCapture extends ffi.Opaque {}

/// Layout matches `WmdVideoFrame` in `wmd_capture.h`.
final class WmdVideoFrameStruct extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> data;
  @ffi.Int32()
  external int size;
  @ffi.Int32()
  external int width;
  @ffi.Int32()
  external int height;
  @ffi.Int64()
  external int ptsUs;
}

/// Layout matches `WmdAudioFrame` in `wmd_capture.h`.
final class WmdAudioFrameStruct extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> data;
  @ffi.Int32()
  external int size;
  @ffi.Int32()
  external int sampleRate;
  @ffi.Int32()
  external int channels;
  @ffi.Int32()
  external int numFrames;
  @ffi.Int64()
  external int ptsUs;
}

// ── @Native FFI bindings ─────────────────────────────────────────────────

@ffi.Native<ffi.Int Function()>(symbol: 'wmd_request_video_access_blocking')
external int _wmdRequestVideoAccessBlocking();

@ffi.Native<ffi.Int Function()>(symbol: 'wmd_request_audio_access_blocking')
external int _wmdRequestAudioAccessBlocking();

@ffi.Native<ffi.Pointer<WmdDeviceList> Function(ffi.Int)>(
    symbol: 'wmd_devices_enumerate')
external ffi.Pointer<WmdDeviceList> _wmdDevicesEnumerate(int kind);

@ffi.Native<ffi.Int Function(ffi.Pointer<WmdDeviceList>)>(
    symbol: 'wmd_devices_count')
external int _wmdDevicesCount(ffi.Pointer<WmdDeviceList> list);

@ffi.Native<ffi.Pointer<pkgffi.Utf8> Function(ffi.Pointer<WmdDeviceList>, ffi.Int)>(
    symbol: 'wmd_devices_id')
external ffi.Pointer<pkgffi.Utf8> _wmdDevicesId(
    ffi.Pointer<WmdDeviceList> list, int idx);

@ffi.Native<ffi.Pointer<pkgffi.Utf8> Function(ffi.Pointer<WmdDeviceList>, ffi.Int)>(
    symbol: 'wmd_devices_name')
external ffi.Pointer<pkgffi.Utf8> _wmdDevicesName(
    ffi.Pointer<WmdDeviceList> list, int idx);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdDeviceList>)>(
    symbol: 'wmd_devices_free')
external void _wmdDevicesFree(ffi.Pointer<WmdDeviceList> list);

@ffi.Native<
    ffi.Pointer<WmdVideoCapture> Function(
        ffi.Pointer<pkgffi.Utf8>, ffi.Int, ffi.Int, ffi.Double)>(
    symbol: 'wmd_video_capture_create')
external ffi.Pointer<WmdVideoCapture> _wmdVideoCaptureCreate(
    ffi.Pointer<pkgffi.Utf8> deviceId, int width, int height, double fps);

@ffi.Native<
    ffi.Pointer<WmdVideoCapture> Function(
        ffi.Pointer<pkgffi.Utf8>, ffi.Int, ffi.Int, ffi.Double)>(
    symbol: 'wmd_video_capture_create_jpeg')
external ffi.Pointer<WmdVideoCapture> _wmdVideoCaptureCreateJpeg(
    ffi.Pointer<pkgffi.Utf8> deviceId, int width, int height, double fps);

@ffi.Native<ffi.Int Function(ffi.Pointer<WmdVideoCapture>)>(
    symbol: 'wmd_video_capture_start')
external int _wmdVideoCaptureStart(ffi.Pointer<WmdVideoCapture> cap);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdVideoCapture>)>(
    symbol: 'wmd_video_capture_stop')
external void _wmdVideoCaptureStop(ffi.Pointer<WmdVideoCapture> cap);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdVideoCapture>)>(
    symbol: 'wmd_video_capture_release')
external void _wmdVideoCaptureRelease(ffi.Pointer<WmdVideoCapture> cap);

@ffi.Native<
    ffi.Pointer<WmdVideoFrameStruct> Function(
        ffi.Pointer<WmdVideoCapture>)>(symbol: 'wmd_video_capture_pop')
external ffi.Pointer<WmdVideoFrameStruct> _wmdVideoCapturePop(
    ffi.Pointer<WmdVideoCapture> cap);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdVideoCapture>, ffi.Int)>(
    symbol: 'wmd_video_capture_set_max_queue')
external void _wmdVideoCaptureSetMaxQueue(
    ffi.Pointer<WmdVideoCapture> cap, int n);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdVideoFrameStruct>)>(
    symbol: 'wmd_video_frame_free')
external void _wmdVideoFrameFree(ffi.Pointer<WmdVideoFrameStruct> f);

@ffi.Native<
    ffi.Pointer<WmdAudioCapture> Function(
        ffi.Pointer<pkgffi.Utf8>, ffi.Int, ffi.Int)>(
    symbol: 'wmd_audio_capture_create')
external ffi.Pointer<WmdAudioCapture> _wmdAudioCaptureCreate(
    ffi.Pointer<pkgffi.Utf8> deviceId, int sampleRate, int channels);

@ffi.Native<ffi.Int Function(ffi.Pointer<WmdAudioCapture>)>(
    symbol: 'wmd_audio_capture_start')
external int _wmdAudioCaptureStart(ffi.Pointer<WmdAudioCapture> cap);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdAudioCapture>)>(
    symbol: 'wmd_audio_capture_stop')
external void _wmdAudioCaptureStop(ffi.Pointer<WmdAudioCapture> cap);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdAudioCapture>)>(
    symbol: 'wmd_audio_capture_release')
external void _wmdAudioCaptureRelease(ffi.Pointer<WmdAudioCapture> cap);

@ffi.Native<
    ffi.Pointer<WmdAudioFrameStruct> Function(
        ffi.Pointer<WmdAudioCapture>)>(symbol: 'wmd_audio_capture_pop')
external ffi.Pointer<WmdAudioFrameStruct> _wmdAudioCapturePop(
    ffi.Pointer<WmdAudioCapture> cap);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdAudioCapture>, ffi.Int)>(
    symbol: 'wmd_audio_capture_set_max_queue')
external void _wmdAudioCaptureSetMaxQueue(
    ffi.Pointer<WmdAudioCapture> cap, int n);

@ffi.Native<ffi.Void Function(ffi.Pointer<WmdAudioFrameStruct>)>(
    symbol: 'wmd_audio_frame_free')
external void _wmdAudioFrameFree(ffi.Pointer<WmdAudioFrameStruct> f);

// ── Higher-level Dart wrappers ───────────────────────────────────────────

bool requestVideoAccessBlocking() => _wmdRequestVideoAccessBlocking() == 1;

bool requestAudioAccessBlocking() => _wmdRequestAudioAccessBlocking() == 1;

/// Native device kind passed to `wmd_devices_enumerate`.
enum WmdDeviceKind {
  video(0),
  audio(1);

  final int nativeValue;
  const WmdDeviceKind(this.nativeValue);
}

final class WmdDeviceEntry {
  final String id;
  final String label;
  final WmdDeviceKind kind;
  const WmdDeviceEntry(this.id, this.label, this.kind);
}

List<WmdDeviceEntry> enumerateDevicesNative(WmdDeviceKind kind) {
  final list = _wmdDevicesEnumerate(kind.nativeValue);
  if (list == ffi.nullptr) return const [];
  try {
    final n = _wmdDevicesCount(list);
    final out = <WmdDeviceEntry>[];
    for (var i = 0; i < n; i++) {
      final idPtr = _wmdDevicesId(list, i);
      final namePtr = _wmdDevicesName(list, i);
      if (idPtr == ffi.nullptr || namePtr == ffi.nullptr) continue;
      out.add(WmdDeviceEntry(
        idPtr.toDartString(),
        namePtr.toDartString(),
        kind,
      ));
    }
    return out;
  } finally {
    _wmdDevicesFree(list);
  }
}

({Uint8List data, int width, int height, int ptsUs})? consumeVideoFrame(
    ffi.Pointer<WmdVideoFrameStruct> p) {
  if (p == ffi.nullptr) return null;
  final s = p.ref;
  // Uint8List.fromList over the asTypedList view skips the zero-init that
  // `Uint8List(size)` + setAll would do — at 30 fps × 460 kB I420 frames
  // that's ~14 MB/s of avoided memset.
  final bytes = Uint8List.fromList(s.data.asTypedList(s.size));
  final result = (
    data: bytes,
    width: s.width,
    height: s.height,
    ptsUs: s.ptsUs,
  );
  _wmdVideoFrameFree(p);
  return result;
}

({
  Uint8List data,
  int sampleRate,
  int channels,
  int numFrames,
  int ptsUs,
})? consumeAudioFrame(ffi.Pointer<WmdAudioFrameStruct> p) {
  if (p == ffi.nullptr) return null;
  final s = p.ref;
  final bytes = Uint8List.fromList(s.data.asTypedList(s.size));
  final result = (
    data: bytes,
    sampleRate: s.sampleRate,
    channels: s.channels,
    numFrames: s.numFrames,
    ptsUs: s.ptsUs,
  );
  _wmdAudioFrameFree(p);
  return result;
}

final class NativeVideoCapture {
  ffi.Pointer<WmdVideoCapture> _ptr;

  NativeVideoCapture._(this._ptr);

  static NativeVideoCapture? create({
    String? deviceId,
    int width = 0,
    int height = 0,
    double fps = 0,
  }) {
    final ptr = pkgffi.using((arena) => _wmdVideoCaptureCreate(
        deviceId == null ? ffi.nullptr : deviceId.toNativeUtf8(allocator: arena),
        width,
        height,
        fps));
    if (ptr == ffi.nullptr) return null;
    return NativeVideoCapture._(ptr);
  }

  /// MJPEG passthrough variant — selects an AVCaptureDeviceFormat whose
  /// native codec is JPEG and delivers the encoded bytes verbatim via
  /// [popFrame] (no decode-then-recompress round-trip).
  ///
  /// Returns `null` when the chosen device has no MJPEG format available
  /// (e.g. macOS built-in FaceTime cameras only expose uncompressed
  /// formats; most external UVC cameras do offer MJPEG).
  static NativeVideoCapture? createJpeg({
    String? deviceId,
    int width = 0,
    int height = 0,
    double fps = 0,
  }) {
    final ptr = pkgffi.using((arena) => _wmdVideoCaptureCreateJpeg(
        deviceId == null
            ? ffi.nullptr
            : deviceId.toNativeUtf8(allocator: arena),
        width,
        height,
        fps));
    if (ptr == ffi.nullptr) return null;
    return NativeVideoCapture._(ptr);
  }

  bool start() {
    if (_ptr == ffi.nullptr) return false;
    return _wmdVideoCaptureStart(_ptr) == 1;
  }

  void stop() {
    if (_ptr != ffi.nullptr) _wmdVideoCaptureStop(_ptr);
  }

  void setMaxQueue(int n) {
    if (_ptr != ffi.nullptr) _wmdVideoCaptureSetMaxQueue(_ptr, n);
  }

  ({Uint8List data, int width, int height, int ptsUs})? popFrame() {
    if (_ptr == ffi.nullptr) return null;
    return consumeVideoFrame(_wmdVideoCapturePop(_ptr));
  }

  void release() {
    if (_ptr == ffi.nullptr) return;
    _wmdVideoCaptureRelease(_ptr);
    _ptr = ffi.nullptr;
  }
}

final class NativeAudioCapture {
  ffi.Pointer<WmdAudioCapture> _ptr;

  NativeAudioCapture._(this._ptr);

  static NativeAudioCapture? create({
    String? deviceId,
    int sampleRate = 48000,
    int channels = 1,
  }) {
    final ptr = pkgffi.using((arena) => _wmdAudioCaptureCreate(
        deviceId == null ? ffi.nullptr : deviceId.toNativeUtf8(allocator: arena),
        sampleRate,
        channels));
    if (ptr == ffi.nullptr) return null;
    return NativeAudioCapture._(ptr);
  }

  bool start() {
    if (_ptr == ffi.nullptr) return false;
    return _wmdAudioCaptureStart(_ptr) == 1;
  }

  void stop() {
    if (_ptr != ffi.nullptr) _wmdAudioCaptureStop(_ptr);
  }

  void setMaxQueue(int n) {
    if (_ptr != ffi.nullptr) _wmdAudioCaptureSetMaxQueue(_ptr, n);
  }

  ({
    Uint8List data,
    int sampleRate,
    int channels,
    int numFrames,
    int ptsUs,
  })? popFrame() {
    if (_ptr == ffi.nullptr) return null;
    return consumeAudioFrame(_wmdAudioCapturePop(_ptr));
  }

  void release() {
    if (_ptr == ffi.nullptr) return;
    _wmdAudioCaptureRelease(_ptr);
    _ptr = ffi.nullptr;
  }
}
