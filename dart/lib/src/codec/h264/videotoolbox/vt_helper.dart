/// VideoToolbox H.264 encoder/decoder helper (macOS/iOS only).
///
/// Hybrid pure-Dart-with-tiny-C-shim design:
///
/// - All VT/CF/CV/CM session management, encode/decode submission, Annex B
///   and I420 extraction lives in this file and uses the ffigen-generated
///   bindings in `bindings.g.dart`.
/// - The VT output callbacks are received by `wvt_enc_callback` /
///   `wvt_dec_callback` in `dart/src/wvt_callback.c`. They run on VT's
///   internal worker threads, CFRetain the resulting CMSampleBuffer /
///   CVImageBuffer, and push a node onto a thread-safe native queue. The
///   Dart drain functions (`wvtEncoderDrainOne` / `wvtDecoderDrainOne`)
///   pull from that queue on the isolate thread and extract the bytes.
///
/// We tried doing the callbacks in pure Dart via
/// `NativeCallable.isolateGroupBound` but that experimental API crashes
/// (`isolate=(nil)`) under realistic multi-stream patterns — interleaved
/// encode/decode across two or more sessions, or back-to-back open/close
/// of encoder+decoder pairs. The C shim sidesteps the problem entirely by
/// keeping the foreign-thread work in C, where threading is well-defined.
/// See the `project_vt_helper_pure_dart.md` memory for the empirical
/// findings.
@ffi.DefaultAsset('package:webdartc/codec/h264/videotoolbox/wvt_callback.dart')
library;

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;

import 'package:ffi/ffi.dart' as pkgffi;

import '../nal_unit_types.dart';
import 'bindings.g.dart';

// ── Apple SDK constants not emitted by ffigen ─────────────────────────────
// Stable Apple ABI values; safe to hardcode.

const int _noErr = 0;
const int _kCFNumberSInt32Type = 3;
const int _kCVReturnSuccess = 0;
// ignore: constant_identifier_names
const int _kCVPixelBufferLock_ReadOnly = 0x00000001;
// ignore: constant_identifier_names
const int _kVTEncodeInfo_FrameDropped = 1 << 1;
// ignore: constant_identifier_names
const int _kVTDecodeInfo_FrameDropped = 1 << 1;

// H.264 / AVCC tunables.
const int _maxNalsPerFrame = 64;
const int _avccLengthSize = 4;
// CMTimeMake denominator for microsecond PTS.
const int _usPerSecond = 1000000;

// ── Library loading ───────────────────────────────────────────────────────

ffi.DynamicLibrary _loadVtLibraries() {
  if (Platform.isMacOS) {
    ffi.DynamicLibrary.open(
        '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation');
    ffi.DynamicLibrary.open(
        '/System/Library/Frameworks/CoreVideo.framework/CoreVideo');
    ffi.DynamicLibrary.open(
        '/System/Library/Frameworks/CoreMedia.framework/CoreMedia');
    ffi.DynamicLibrary.open(
        '/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox');
  } else if (!Platform.isIOS) {
    throw UnsupportedError(
        'VideoToolbox helper is only available on macOS and iOS');
  }
  // On iOS the frameworks must be linked into the app bundle; the symbols
  // resolve via DynamicLibrary.process().
  return ffi.DynamicLibrary.process();
}

final ffi.DynamicLibrary _vtLib = _loadVtLibraries();
final VtBindings _vt = VtBindings(_vtLib);

// Pointer-typed accessors for CF dictionary callback structs. The bindings
// expose them as values (`.ref`), but CFDictionaryCreate wants pointers.
final ffi.Pointer<CFDictionaryKeyCallBacks> _kCFTypeDictionaryKeyCallBacksPtr =
    _vtLib.lookup<CFDictionaryKeyCallBacks>('kCFTypeDictionaryKeyCallBacks');
final ffi.Pointer<CFDictionaryValueCallBacks>
    _kCFTypeDictionaryValueCallBacksPtr =
    _vtLib.lookup<CFDictionaryValueCallBacks>('kCFTypeDictionaryValueCallBacks');

// `kCFBooleanFalse` is not in the ffigen-generated globals (only True is).
final CFBooleanRef _kCFBooleanFalse =
    _vtLib.lookup<CFBooleanRef>('kCFBooleanFalse').value;

// ── C callback shim bindings ─────────────────────────────────────────────

/// Loaded once at startup. The dylib is registered as a code asset by
/// `hook/build.dart`; on macOS/iOS it ends up in the process's symbol
/// table, so a process-wide lookup finds the symbols. We also keep this
/// `final` reference so subsequent `_vtLib`-style usage stays consistent.
@ffi.Native<
    ffi.Pointer<WvtEncQueue> Function()>(symbol: 'wvt_enc_queue_create')
external ffi.Pointer<WvtEncQueue> _wvtEncQueueCreate();

@ffi.Native<ffi.Void Function(ffi.Pointer<WvtEncQueue>)>(
    symbol: 'wvt_enc_queue_release')
external void _wvtEncQueueRelease(ffi.Pointer<WvtEncQueue> q);

@ffi.Native<
    ffi.Pointer<WvtEncNode> Function(
        ffi.Pointer<WvtEncQueue>)>(symbol: 'wvt_enc_queue_pop')
external ffi.Pointer<WvtEncNode> _wvtEncQueuePop(
    ffi.Pointer<WvtEncQueue> q);

@ffi.Native<ffi.Void Function(ffi.Pointer<WvtEncNode>)>(
    symbol: 'wvt_enc_node_free')
external void _wvtEncNodeFree(ffi.Pointer<WvtEncNode> n);

@ffi.Native<
    ffi.Void Function(
      ffi.Pointer<ffi.Void>,
      ffi.Pointer<ffi.Void>,
      ffi.Int,
      ffi.UnsignedInt,
      CMSampleBufferRef,
    )>(symbol: 'wvt_enc_callback')
external void _wvtEncCallback(
    ffi.Pointer<ffi.Void> outputRefCon,
    ffi.Pointer<ffi.Void> sourceRefCon,
    int status,
    int infoFlags,
    CMSampleBufferRef sb);

@ffi.Native<
    ffi.Pointer<WvtDecQueue> Function()>(symbol: 'wvt_dec_queue_create')
external ffi.Pointer<WvtDecQueue> _wvtDecQueueCreate();

@ffi.Native<ffi.Void Function(ffi.Pointer<WvtDecQueue>)>(
    symbol: 'wvt_dec_queue_release')
external void _wvtDecQueueRelease(ffi.Pointer<WvtDecQueue> q);

@ffi.Native<
    ffi.Pointer<WvtDecNode> Function(
        ffi.Pointer<WvtDecQueue>)>(symbol: 'wvt_dec_queue_pop')
external ffi.Pointer<WvtDecNode> _wvtDecQueuePop(
    ffi.Pointer<WvtDecQueue> q);

@ffi.Native<ffi.Void Function(ffi.Pointer<WvtDecNode>)>(
    symbol: 'wvt_dec_node_free')
external void _wvtDecNodeFree(ffi.Pointer<WvtDecNode> n);

@ffi.Native<
    ffi.Void Function(
      ffi.Pointer<ffi.Void>,
      ffi.Pointer<ffi.Void>,
      ffi.Int,
      ffi.UnsignedInt,
      CVImageBufferRef,
      CMTime,
      CMTime,
    )>(symbol: 'wvt_dec_callback')
external void _wvtDecCallback(
    ffi.Pointer<ffi.Void> outputRefCon,
    ffi.Pointer<ffi.Void> sourceRefCon,
    int status,
    int infoFlags,
    CVImageBufferRef img,
    CMTime pts,
    CMTime dur);

/// Function-pointer of `wvt_enc_callback`, suitable for passing to
/// `VTCompressionSessionCreate`.
final ffi.Pointer<
    ffi.NativeFunction<
        ffi.Void Function(
          ffi.Pointer<ffi.Void>,
          ffi.Pointer<ffi.Void>,
          ffi.Int,
          ffi.UnsignedInt,
          CMSampleBufferRef,
        )>> _wvtEncCallbackPtr = ffi.Native.addressOf(_wvtEncCallback);

/// Function-pointer of `wvt_dec_callback`, suitable for installing in a
/// `VTDecompressionOutputCallbackRecord`.
final ffi.Pointer<
    ffi.NativeFunction<
        ffi.Void Function(
          ffi.Pointer<ffi.Void>,
          ffi.Pointer<ffi.Void>,
          ffi.Int,
          ffi.UnsignedInt,
          CVImageBufferRef,
          CMTime,
          CMTime,
        )>> _wvtDecCallbackPtr = ffi.Native.addressOf(_wvtDecCallback);

// ── Public opaque handles (mirror the prior C API shape) ──────────────────

/// Opaque encoder queue (struct lives in C; pthread_mutex_t size varies).
final class WvtEncQueue extends ffi.Opaque {}

/// One encoded-frame node enqueued by the C callback. Layout must match
/// `WvtEncNode` in `wvt_callback.h`.
final class WvtEncNode extends ffi.Struct {
  external CMSampleBufferRef sb;
  @ffi.Int64()
  external int ptsUs;
  @ffi.Int32()
  external int status;
  @ffi.Int32()
  external int infoFlags;
  external ffi.Pointer<WvtEncNode> next;
}

/// Encoder state. Public as a `Pointer<WvtEncoder>` to match the prior API.
final class WvtEncoder extends ffi.Struct {
  external VTCompressionSessionRef session;
  @ffi.Int32()
  external int width;
  @ffi.Int32()
  external int height;
  external ffi.Pointer<WvtEncQueue> queue;
  // Long-lived CF objects, built once at create-time and CFRetained for the
  // session's lifetime.
  external CFDictionaryRef pixelBufferAttrs;
  external CFDictionaryRef forceKeyframeProps;
}

/// Encoded output (Annex B bitstream). Allocated by `wvtEncoderDrainOne`
/// after extracting bytes from a queued CMSampleBuffer.
final class WvtEncoderOutput extends ffi.Struct {
  external ffi.Pointer<ffi.Uint8> data;
  @ffi.Int32()
  external int size;
  @ffi.Int32()
  external int isKeyframe;
  @ffi.Int64()
  external int ptsUs;
}

/// Opaque decoder queue.
final class WvtDecQueue extends ffi.Opaque {}

/// Decoder queue node — layout matches `WvtDecNode` in `wvt_callback.h`.
final class WvtDecNode extends ffi.Struct {
  external CVImageBufferRef img;
  @ffi.Int64()
  external int ptsUs;
  @ffi.Int32()
  external int status;
  @ffi.Int32()
  external int infoFlags;
  external ffi.Pointer<WvtDecNode> next;
}

/// Decoder state.
final class WvtDecoder extends ffi.Struct {
  external VTDecompressionSessionRef session;
  external CMVideoFormatDescriptionRef fmtDesc;
  @ffi.Int32()
  external int width;
  @ffi.Int32()
  external int height;
  external ffi.Pointer<ffi.Uint8> sps;
  @ffi.Int32()
  external int spsSize;
  external ffi.Pointer<ffi.Uint8> pps;
  @ffi.Int32()
  external int ppsSize;
  external ffi.Pointer<WvtDecQueue> queue;
  // Native-side callback record kept alive for the session's lifetime.
  external ffi.Pointer<VTDecompressionOutputCallbackRecord> cbRecord;
}

/// Decoded I420 frame. Allocated by `wvtDecoderDrainOne` after pulling a
/// CVPixelBuffer off the queue and copying its planes to a contiguous
/// I420 buffer.
final class WvtDecodedFrame extends ffi.Struct {
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

// ── ABI version (kept for compat with callers / tests) ────────────────────

const int _abiVersion = 3;
int webdartcVtHelperAbiVersion() => _abiVersion;

// ── Helpers ───────────────────────────────────────────────────────────────

CFNumberRef _makeInt32CFNumber(int v) {
  final box = pkgffi.calloc<ffi.Int32>();
  box.value = v;
  final num = _vt.CFNumberCreate(
      _vt.kCFAllocatorDefault, _kCFNumberSInt32Type, box.cast());
  pkgffi.calloc.free(box);
  return num;
}

void _setSessionInt32(VTCompressionSessionRef s, CFStringRef key, int v) {
  final n = _makeInt32CFNumber(v);
  _vt.VTSessionSetProperty(s.cast(), key, n.cast());
  _vt.CFRelease(n.cast());
}

/// `{kCVPixelBufferIOSurfacePropertiesKey: {}}` — passed to
/// `CVPixelBufferCreate` so VT allocates IOSurface-backed buffers.
CFDictionaryRef _buildIOSurfacePixelBufferAttrs() {
  final empty = _vt.CFDictionaryCreate(
      _vt.kCFAllocatorDefault,
      ffi.nullptr,
      ffi.nullptr,
      0,
      _kCFTypeDictionaryKeyCallBacksPtr,
      _kCFTypeDictionaryValueCallBacksPtr);
  final keys = pkgffi.calloc<ffi.Pointer<ffi.Void>>();
  final vals = pkgffi.calloc<ffi.Pointer<ffi.Void>>();
  keys.value = _vt.kCVPixelBufferIOSurfacePropertiesKey.cast();
  vals.value = empty.cast();
  final attrs = _vt.CFDictionaryCreate(
      _vt.kCFAllocatorDefault,
      keys,
      vals,
      1,
      _kCFTypeDictionaryKeyCallBacksPtr,
      _kCFTypeDictionaryValueCallBacksPtr);
  pkgffi.calloc.free(keys);
  pkgffi.calloc.free(vals);
  _vt.CFRelease(empty.cast());
  return attrs;
}

/// `{kVTEncodeFrameOptionKey_ForceKeyFrame: kCFBooleanTrue}` — immutable,
/// reused across frames.
CFDictionaryRef _buildForceKeyframeProps() {
  final fk = pkgffi.calloc<ffi.Pointer<ffi.Void>>();
  final fv = pkgffi.calloc<ffi.Pointer<ffi.Void>>();
  fk.value = _vt.kVTEncodeFrameOptionKey_ForceKeyFrame.cast();
  fv.value = _vt.kCFBooleanTrue.cast();
  final props = _vt.CFDictionaryCreate(
      _vt.kCFAllocatorDefault,
      fk,
      fv,
      1,
      _kCFTypeDictionaryKeyCallBacksPtr,
      _kCFTypeDictionaryValueCallBacksPtr);
  pkgffi.calloc.free(fk);
  pkgffi.calloc.free(fv);
  return props;
}

void _copyPlane(ffi.Pointer<ffi.Uint8> dst, int dstStride,
    ffi.Pointer<ffi.Uint8> src, int srcStride, int w, int h) {
  if (dstStride == srcStride && srcStride == w) {
    final n = w * h;
    dst.asTypedList(n).setRange(0, n, src.asTypedList(n));
    return;
  }
  for (int r = 0; r < h; r++) {
    (dst + r * dstStride)
        .asTypedList(w)
        .setRange(0, w, (src + r * srcStride).asTypedList(w));
  }
}

// ── Encoder: public API ───────────────────────────────────────────────────

ffi.Pointer<WvtEncoder> wvtEncoderCreate(
    int width, int height, int bitrate, int fps, int keyframeInterval) {
  final enc = pkgffi.calloc<WvtEncoder>();
  enc.ref.width = width;
  enc.ref.height = height;
  enc.ref.queue = _wvtEncQueueCreate();
  if (enc.ref.queue == ffi.nullptr) {
    pkgffi.calloc.free(enc);
    return ffi.nullptr;
  }

  final sessionPP = pkgffi.calloc<VTCompressionSessionRef>();
  final s = _vt.VTCompressionSessionCreate(
      _vt.kCFAllocatorDefault,
      width,
      height,
      kCMVideoCodecType_H264,
      ffi.nullptr.cast(), // encoderSpecification
      ffi.nullptr.cast(), // sourceImageBufferAttributes
      _vt.kCFAllocatorDefault,
      _wvtEncCallbackPtr,
      enc.ref.queue.cast(), // outputCallbackRefCon
      sessionPP);
  final session = sessionPP.value;
  pkgffi.calloc.free(sessionPP);
  if (s != _noErr) {
    _wvtEncQueueRelease(enc.ref.queue);
    pkgffi.calloc.free(enc);
    return ffi.nullptr;
  }
  enc.ref.session = session;

  _vt.VTSessionSetProperty(session.cast(),
      _vt.kVTCompressionPropertyKey_RealTime, _vt.kCFBooleanTrue.cast());
  _vt.VTSessionSetProperty(
      session.cast(),
      _vt.kVTCompressionPropertyKey_AllowFrameReordering,
      _kCFBooleanFalse.cast());
  _vt.VTSessionSetProperty(
      session.cast(),
      _vt.kVTCompressionPropertyKey_ProfileLevel,
      _vt.kVTProfileLevel_H264_Baseline_AutoLevel.cast());
  _setSessionInt32(
      session, _vt.kVTCompressionPropertyKey_AverageBitRate, bitrate);
  _setSessionInt32(session,
      _vt.kVTCompressionPropertyKey_MaxKeyFrameInterval, keyframeInterval);
  _setSessionInt32(
      session, _vt.kVTCompressionPropertyKey_ExpectedFrameRate, fps);

  _vt.VTCompressionSessionPrepareToEncodeFrames(session);

  enc.ref.pixelBufferAttrs = _buildIOSurfacePixelBufferAttrs();
  enc.ref.forceKeyframeProps = _buildForceKeyframeProps();
  return enc;
}

int wvtEncoderEncode(
  ffi.Pointer<WvtEncoder> enc,
  ffi.Pointer<ffi.Uint8> y,
  ffi.Pointer<ffi.Uint8> u,
  ffi.Pointer<ffi.Uint8> v,
  int yStride,
  int uvStride,
  int ptsUs,
  int forceKeyframe,
) {
  if (enc == ffi.nullptr || enc.ref.session == ffi.nullptr) return -1;

  final pixPP = pkgffi.calloc<CVPixelBufferRef>();
  int s = _vt.CVPixelBufferCreate(
      _vt.kCFAllocatorDefault,
      enc.ref.width,
      enc.ref.height,
      kCVPixelFormatType_420YpCbCr8Planar,
      enc.ref.pixelBufferAttrs,
      pixPP);
  final pix = pixPP.value;
  pkgffi.calloc.free(pixPP);
  if (s != _noErr || pix == ffi.nullptr) return -2;

  if (_vt.CVPixelBufferLockBaseAddress(pix, 0) != _kCVReturnSuccess) {
    _vt.CVPixelBufferRelease(pix);
    return -3;
  }
  _copyPlane(_vt.CVPixelBufferGetBaseAddressOfPlane(pix, 0).cast(),
      _vt.CVPixelBufferGetBytesPerRowOfPlane(pix, 0),
      y, yStride, enc.ref.width, enc.ref.height);
  final uvW = enc.ref.width >> 1;
  final uvH = enc.ref.height >> 1;
  _copyPlane(_vt.CVPixelBufferGetBaseAddressOfPlane(pix, 1).cast(),
      _vt.CVPixelBufferGetBytesPerRowOfPlane(pix, 1), u, uvStride, uvW, uvH);
  _copyPlane(_vt.CVPixelBufferGetBaseAddressOfPlane(pix, 2).cast(),
      _vt.CVPixelBufferGetBytesPerRowOfPlane(pix, 2), v, uvStride, uvW, uvH);
  _vt.CVPixelBufferUnlockBaseAddress(pix, 0);

  final frameProps = forceKeyframe != 0
      ? enc.ref.forceKeyframeProps
      : ffi.nullptr.cast<CFDictionary>();

  // PTS rides in the source_ref_con slot directly (cast int → pointer
  // value); the C callback casts it back. Avoids a malloc/free per frame.
  final pts = _vt.CMTimeMake(ptsUs, _usPerSecond);
  final dur = _vt.kCMTimeInvalid;
  s = _vt.VTCompressionSessionEncodeFrame(enc.ref.session, pix, pts, dur,
      frameProps, ffi.Pointer.fromAddress(ptsUs), ffi.nullptr.cast());
  _vt.CVPixelBufferRelease(pix);
  if (s != _noErr) return -4;

  // Synchronously drain so the queue is populated by the time we return.
  _vt.VTCompressionSessionCompleteFrames(enc.ref.session, _vt.kCMTimeInvalid);
  return 0;
}

ffi.Pointer<WvtEncoderOutput> wvtEncoderDrainOne(
    ffi.Pointer<WvtEncoder> enc) {
  if (enc == ffi.nullptr) return ffi.nullptr;
  while (true) {
    final node = _wvtEncQueuePop(enc.ref.queue);
    if (node == ffi.nullptr) return ffi.nullptr;
    final out = _buildOutputFromNode(node);
    _wvtEncNodeFree(node);
    if (out != ffi.nullptr) return out;
    // Dropped/error frame — try the next queued node.
  }
}

/// Convert a queued `WvtEncNode` (CMSampleBuffer + PTS) into a Dart-owned
/// `WvtEncoderOutput` with Annex B bytes. Returns `nullptr` for dropped or
/// errored frames.
ffi.Pointer<WvtEncoderOutput> _buildOutputFromNode(
    ffi.Pointer<WvtEncNode> node) {
  if (node.ref.status != _noErr || node.ref.sb == ffi.nullptr) {
    return ffi.nullptr;
  }
  if ((node.ref.infoFlags & _kVTEncodeInfo_FrameDropped) != 0) {
    return ffi.nullptr;
  }
  final dataPP = pkgffi.calloc<ffi.Pointer<ffi.Uint8>>();
  final sizeP = pkgffi.calloc<ffi.Int32>();
  final isKeyP = pkgffi.calloc<ffi.Int32>();
  final rc = _extractAnnexB(node.ref.sb, dataPP, sizeP, isKeyP);
  final data = dataPP.value;
  final size = sizeP.value;
  final isKey = isKeyP.value;
  pkgffi.calloc.free(dataPP);
  pkgffi.calloc.free(sizeP);
  pkgffi.calloc.free(isKeyP);
  if (rc != 0) return ffi.nullptr;

  final out = pkgffi.calloc<WvtEncoderOutput>();
  out.ref.data = data;
  out.ref.size = size;
  out.ref.isKeyframe = isKey;
  out.ref.ptsUs = node.ref.ptsUs;
  return out;
}

/// Walk a CMSampleBuffer's AVCC payload, prepend SPS/PPS for keyframes,
/// and return a malloc'd Annex B blob.
int _extractAnnexB(
  CMSampleBufferRef sb,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outData,
  ffi.Pointer<ffi.Int32> outSize,
  ffi.Pointer<ffi.Int32> outIsKey,
) {
  // Keyframe? (NotSync attachment indicates non-keyframe.)
  int isKey = 1;
  final attachments = _vt.CMSampleBufferGetSampleAttachmentsArray(sb, 0);
  if (attachments != ffi.nullptr && _vt.CFArrayGetCount(attachments) > 0) {
    final dictPtr = _vt.CFArrayGetValueAtIndex(attachments, 0);
    final dict = dictPtr.cast<CFDictionary>();
    if (_vt.CFDictionaryContainsKey(
            dict, _vt.kCMSampleAttachmentKey_NotSync.cast()) !=
        0) {
      isKey = 0;
    }
  }
  outIsKey.value = isKey;

  final block = _vt.CMSampleBufferGetDataBuffer(sb);
  if (block == ffi.nullptr) return -1;

  final (blockPtr, blockSize) = _getCMBlockBufferDataPointer(block);
  if (blockPtr == ffi.nullptr) return -2;

  // For keyframes, fish SPS/PPS out of the format description.
  ffi.Pointer<ffi.Uint8> spsData = ffi.nullptr;
  int spsSize = 0;
  ffi.Pointer<ffi.Uint8> ppsData = ffi.nullptr;
  int ppsSize = 0;
  int nalHeaderSize = _avccLengthSize;

  if (isKey == 1) {
    final fmt = _vt.CMSampleBufferGetFormatDescription(sb);
    final (paramCount, headerSzOut) = _queryH264ParameterSetCount(fmt);
    if (paramCount >= 2) {
      nalHeaderSize = headerSzOut;
      (spsData, spsSize) = _getH264ParameterSet(fmt, 0);
      (ppsData, ppsSize) = _getH264ParameterSet(fmt, 1);
    }
  }

  // Compute total output size.
  int total = 0;
  if (spsData != ffi.nullptr) total += _avccLengthSize + spsSize;
  if (ppsData != ffi.nullptr) total += _avccLengthSize + ppsSize;
  final inBytes = blockPtr.cast<ffi.Uint8>();
  int pos = 0;
  while (pos + nalHeaderSize <= blockSize) {
    int nalLen = 0;
    for (int i = 0; i < nalHeaderSize; i++) {
      nalLen = (nalLen << 8) | inBytes[pos + i];
    }
    total += _avccLengthSize + nalLen;
    pos += nalHeaderSize + nalLen;
  }

  final out = pkgffi.malloc<ffi.Uint8>(total);
  int w = 0;
  if (spsData != ffi.nullptr) {
    w = _writeAnnexBNal(out, w, spsData, spsSize);
  }
  if (ppsData != ffi.nullptr) {
    w = _writeAnnexBNal(out, w, ppsData, ppsSize);
  }
  pos = 0;
  while (pos + nalHeaderSize <= blockSize) {
    int nalLen = 0;
    for (int i = 0; i < nalHeaderSize; i++) {
      nalLen = (nalLen << 8) | inBytes[pos + i];
    }
    w = _writeAnnexBNal(out, w, inBytes + pos + nalHeaderSize, nalLen);
    pos += nalHeaderSize + nalLen;
  }

  outData.value = out;
  outSize.value = w;
  return 0;
}

/// Returns `(blockPtr, blockSize)` for the data backing a CMBlockBuffer.
/// `blockPtr == nullptr` indicates failure.
(ffi.Pointer<ffi.Char>, int) _getCMBlockBufferDataPointer(
    CMBlockBufferRef block) {
  final sizePtr = pkgffi.calloc<ffi.Size>();
  final ptrPtr = pkgffi.calloc<ffi.Pointer<ffi.Char>>();
  final s = _vt.CMBlockBufferGetDataPointer(
      block, 0, ffi.nullptr.cast(), sizePtr, ptrPtr);
  final size = sizePtr.value;
  final ptr = ptrPtr.value;
  pkgffi.calloc.free(sizePtr);
  pkgffi.calloc.free(ptrPtr);
  if (s != _noErr) return (ffi.nullptr, 0);
  return (ptr, size);
}

/// Returns `(paramCount, nalHeaderLength)` for the H.264 parameter sets in
/// `fmt`, or `(0, 0)` on failure.
(int, int) _queryH264ParameterSetCount(CMVideoFormatDescriptionRef fmt) {
  final paramCountPtr = pkgffi.calloc<ffi.Size>();
  final headerSzPtr = pkgffi.calloc<ffi.Int>();
  final ok = _vt.CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
      fmt, 0, ffi.nullptr, ffi.nullptr, paramCountPtr, headerSzPtr);
  final paramCount = paramCountPtr.value;
  final headerSz = headerSzPtr.value;
  pkgffi.calloc.free(paramCountPtr);
  pkgffi.calloc.free(headerSzPtr);
  return (ok == _noErr ? paramCount : 0, ok == _noErr ? headerSz : 0);
}

/// Read parameter set `index` (0=SPS, 1=PPS for H.264) from a CMVideoFormat
/// description. Returns `(nullptr, 0)` if not present.
(ffi.Pointer<ffi.Uint8>, int) _getH264ParameterSet(
    CMVideoFormatDescriptionRef fmt, int index) {
  final dataPP = pkgffi.calloc<ffi.Pointer<ffi.Uint8>>();
  final sizePtr = pkgffi.calloc<ffi.Size>();
  _vt.CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
      fmt, index, dataPP, sizePtr, ffi.nullptr, ffi.nullptr);
  final data = dataPP.value;
  final size = sizePtr.value;
  pkgffi.calloc.free(dataPP);
  pkgffi.calloc.free(sizePtr);
  return (data, size);
}

/// Append `00 00 00 01 <payload>` to `out` starting at `w`. Returns the
/// new write offset.
int _writeAnnexBNal(
    ffi.Pointer<ffi.Uint8> out, int w, ffi.Pointer<ffi.Uint8> src, int n) {
  final outList = out.asTypedList(w + _avccLengthSize + n);
  outList[w + 0] = 0;
  outList[w + 1] = 0;
  outList[w + 2] = 0;
  outList[w + 3] = 1;
  outList.setRange(w + _avccLengthSize, w + _avccLengthSize + n,
      src.asTypedList(n));
  return w + _avccLengthSize + n;
}

int wvtEncoderOutputSize(ffi.Pointer<WvtEncoderOutput> out) =>
    out.ref.size;
int wvtEncoderOutputIsKeyframe(ffi.Pointer<WvtEncoderOutput> out) =>
    out.ref.isKeyframe;
int wvtEncoderOutputPtsUs(ffi.Pointer<WvtEncoderOutput> out) =>
    out.ref.ptsUs;
ffi.Pointer<ffi.Uint8> wvtEncoderOutputData(
        ffi.Pointer<WvtEncoderOutput> out) =>
    out.ref.data;
void wvtEncoderOutputFree(ffi.Pointer<WvtEncoderOutput> out) {
  if (out == ffi.nullptr) return;
  if (out.ref.data != ffi.nullptr) pkgffi.malloc.free(out.ref.data);
  pkgffi.calloc.free(out);
}

void wvtEncoderDestroy(ffi.Pointer<WvtEncoder> enc) {
  if (enc == ffi.nullptr) return;
  if (enc.ref.session != ffi.nullptr) {
    _vt.VTCompressionSessionCompleteFrames(
        enc.ref.session, _vt.kCMTimeInvalid);
    _vt.VTCompressionSessionInvalidate(enc.ref.session);
    _vt.CFRelease(enc.ref.session.cast());
  }
  if (enc.ref.pixelBufferAttrs != ffi.nullptr) {
    _vt.CFRelease(enc.ref.pixelBufferAttrs.cast());
  }
  if (enc.ref.forceKeyframeProps != ffi.nullptr) {
    _vt.CFRelease(enc.ref.forceKeyframeProps.cast());
  }
  if (enc.ref.queue != ffi.nullptr) {
    _wvtEncQueueRelease(enc.ref.queue);
  }
  pkgffi.calloc.free(enc);
}

// ── Decoder: public API ───────────────────────────────────────────────────

ffi.Pointer<WvtDecoder> wvtDecoderCreate() {
  final dec = pkgffi.calloc<WvtDecoder>();
  dec.ref.queue = _wvtDecQueueCreate();
  if (dec.ref.queue == ffi.nullptr) {
    pkgffi.calloc.free(dec);
    return ffi.nullptr;
  }
  return dec;
}

int _setupDecoderSession(ffi.Pointer<WvtDecoder> dec,
    ffi.Pointer<ffi.Uint8> sps, int spsSize,
    ffi.Pointer<ffi.Uint8> pps, int ppsSize) {
  if (dec.ref.session != ffi.nullptr) {
    _vt.VTDecompressionSessionInvalidate(dec.ref.session);
    _vt.CFRelease(dec.ref.session.cast());
    dec.ref.session = ffi.nullptr.cast();
  }
  if (dec.ref.fmtDesc != ffi.nullptr) {
    _vt.CFRelease(dec.ref.fmtDesc.cast());
    dec.ref.fmtDesc = ffi.nullptr.cast();
  }

  final params = pkgffi.calloc<ffi.Pointer<ffi.Uint8>>(2);
  final sizes = pkgffi.calloc<ffi.Size>(2);
  params[0] = sps;
  params[1] = pps;
  sizes[0] = spsSize;
  sizes[1] = ppsSize;
  final fmtPP = pkgffi.calloc<CMVideoFormatDescriptionRef>();
  int s = _vt.CMVideoFormatDescriptionCreateFromH264ParameterSets(
      _vt.kCFAllocatorDefault, 2, params, sizes, _avccLengthSize, fmtPP);
  pkgffi.calloc.free(params);
  pkgffi.calloc.free(sizes);
  final fmt = fmtPP.value;
  pkgffi.calloc.free(fmtPP);
  if (s != _noErr) return -1;
  dec.ref.fmtDesc = fmt;

  final dims = _vt.CMVideoFormatDescriptionGetDimensions(fmt);
  dec.ref.width = dims.width;
  dec.ref.height = dims.height;

  // Force I420 output to match the C helper's behavior.
  final pfNum = _makeInt32CFNumber(kCVPixelFormatType_420YpCbCr8Planar);
  final keys = pkgffi.calloc<ffi.Pointer<ffi.Void>>();
  final vals = pkgffi.calloc<ffi.Pointer<ffi.Void>>();
  keys.value = _vt.kCVPixelBufferPixelFormatTypeKey.cast();
  vals.value = pfNum.cast();
  final attrs = _vt.CFDictionaryCreate(
      _vt.kCFAllocatorDefault,
      keys,
      vals,
      1,
      _kCFTypeDictionaryKeyCallBacksPtr,
      _kCFTypeDictionaryValueCallBacksPtr);
  pkgffi.calloc.free(keys);
  pkgffi.calloc.free(vals);
  _vt.CFRelease(pfNum.cast());

  // The callback record is held by VT for the session's lifetime.
  if (dec.ref.cbRecord == ffi.nullptr) {
    dec.ref.cbRecord = pkgffi.calloc<VTDecompressionOutputCallbackRecord>();
  }
  dec.ref.cbRecord.ref.decompressionOutputCallback = _wvtDecCallbackPtr;
  dec.ref.cbRecord.ref.decompressionOutputRefCon = dec.ref.queue.cast();

  final sessPP = pkgffi.calloc<VTDecompressionSessionRef>();
  s = _vt.VTDecompressionSessionCreate(_vt.kCFAllocatorDefault, fmt,
      ffi.nullptr.cast(), attrs, dec.ref.cbRecord, sessPP);
  _vt.CFRelease(attrs.cast());
  final sess = sessPP.value;
  pkgffi.calloc.free(sessPP);
  if (s != _noErr) {
    _vt.CFRelease(fmt.cast());
    dec.ref.fmtDesc = ffi.nullptr.cast();
    return -2;
  }
  dec.ref.session = sess;

  // Cache SPS/PPS for change detection.
  if (dec.ref.sps != ffi.nullptr) pkgffi.malloc.free(dec.ref.sps);
  dec.ref.sps = pkgffi.malloc<ffi.Uint8>(spsSize);
  dec.ref.sps.asTypedList(spsSize).setRange(0, spsSize, sps.asTypedList(spsSize));
  dec.ref.spsSize = spsSize;
  if (dec.ref.pps != ffi.nullptr) pkgffi.malloc.free(dec.ref.pps);
  dec.ref.pps = pkgffi.malloc<ffi.Uint8>(ppsSize);
  dec.ref.pps.asTypedList(ppsSize).setRange(0, ppsSize, pps.asTypedList(ppsSize));
  dec.ref.ppsSize = ppsSize;
  return 0;
}

int _findStartCode(ffi.Pointer<ffi.Uint8> buf, int bufSize, int start,
    ffi.Pointer<ffi.Int32> scSizeOut) {
  for (int i = start; i + 2 < bufSize; i++) {
    if (buf[i] == 0 && buf[i + 1] == 0) {
      if (buf[i + 2] == 1) {
        scSizeOut.value = 3;
        return i;
      }
      if (i + 3 < bufSize && buf[i + 2] == 0 && buf[i + 3] == 1) {
        scSizeOut.value = 4;
        return i;
      }
    }
  }
  return -1;
}

int wvtDecoderDecode(
  ffi.Pointer<WvtDecoder> dec,
  ffi.Pointer<ffi.Uint8> annexB,
  int annexBSize,
  int ptsUs,
) {
  if (dec == ffi.nullptr) return -1;

  final nalOff = pkgffi.calloc<ffi.Int32>(_maxNalsPerFrame);
  final nalSz = pkgffi.calloc<ffi.Int32>(_maxNalsPerFrame);
  final sliceIdx = pkgffi.calloc<ffi.Int32>(_maxNalsPerFrame);
  ffi.Pointer<ffi.Uint8> avcc = ffi.nullptr;
  int avccSize = 0;
  try {
    final scSize = pkgffi.calloc<ffi.Int32>();
    int nalCount = 0;
    int pos = 0;
    while (pos < annexBSize && nalCount < _maxNalsPerFrame) {
      final p = _findStartCode(annexB, annexBSize, pos, scSize);
      if (p < 0) break;
      final nalStart = p + scSize.value;
      final p2 = _findStartCode(annexB, annexBSize, nalStart, scSize);
      final nalEnd = (p2 < 0) ? annexBSize : p2;
      nalOff[nalCount] = nalStart;
      nalSz[nalCount] = nalEnd - nalStart;
      nalCount++;
      pos = nalEnd;
    }
    pkgffi.calloc.free(scSize);
    if (nalCount == 0) return -2;

    ffi.Pointer<ffi.Uint8> sps = ffi.nullptr;
    int spsSize = 0;
    ffi.Pointer<ffi.Uint8> pps = ffi.nullptr;
    int ppsSize = 0;
    int sliceCount = 0;
    for (int i = 0; i < nalCount; i++) {
      final type = annexB[nalOff[i]] & H264NalType.mask;
      if (type == H264NalType.sps) {
        sps = annexB + nalOff[i];
        spsSize = nalSz[i];
      } else if (type == H264NalType.pps) {
        pps = annexB + nalOff[i];
        ppsSize = nalSz[i];
      } else {
        sliceIdx[sliceCount++] = i;
      }
    }

    if (sps != ffi.nullptr && pps != ffi.nullptr) {
      final needSetup = dec.ref.session == ffi.nullptr ||
          spsSize != dec.ref.spsSize ||
          ppsSize != dec.ref.ppsSize ||
          !_bytesEqual(sps, dec.ref.sps, spsSize) ||
          !_bytesEqual(pps, dec.ref.pps, ppsSize);
      if (needSetup &&
          _setupDecoderSession(dec, sps, spsSize, pps, ppsSize) != 0) {
        return -3;
      }
    }
    if (dec.ref.session == ffi.nullptr) return -4;
    if (sliceCount == 0) return 0;

    // Convert slices to AVCC (length-prefixed).
    for (int i = 0; i < sliceCount; i++) {
      avccSize += _avccLengthSize + nalSz[sliceIdx[i]];
    }
    avcc = pkgffi.malloc<ffi.Uint8>(avccSize);
    final avccList = avcc.asTypedList(avccSize);
    int w = 0;
    for (int i = 0; i < sliceCount; i++) {
      final idx = sliceIdx[i];
      final sz = nalSz[idx];
      avccList[w++] = (sz >> 24) & 0xFF;
      avccList[w++] = (sz >> 16) & 0xFF;
      avccList[w++] = (sz >> 8) & 0xFF;
      avccList[w++] = sz & 0xFF;
      avccList.setRange(w, w + sz, (annexB + nalOff[idx]).asTypedList(sz));
      w += sz;
    }
  } finally {
    pkgffi.calloc.free(nalOff);
    pkgffi.calloc.free(nalSz);
    pkgffi.calloc.free(sliceIdx);
  }

  final blockPP = pkgffi.calloc<CMBlockBufferRef>();
  int s = _vt.CMBlockBufferCreateWithMemoryBlock(
      _vt.kCFAllocatorDefault,
      avcc.cast(),
      avccSize,
      _vt.kCFAllocatorMalloc,
      ffi.nullptr.cast(),
      0,
      avccSize,
      0,
      blockPP);
  final block = blockPP.value;
  pkgffi.calloc.free(blockPP);
  if (s != _noErr) {
    pkgffi.malloc.free(avcc);
    return -5;
  }

  final timing = pkgffi.calloc<CMSampleTimingInfo>();
  timing.ref.duration = _vt.kCMTimeInvalid;
  timing.ref.presentationTimeStamp = _vt.CMTimeMake(ptsUs, _usPerSecond);
  timing.ref.decodeTimeStamp = _vt.kCMTimeInvalid;
  final sampleSize = pkgffi.calloc<ffi.Size>();
  sampleSize.value = avccSize;
  final samplePP = pkgffi.calloc<CMSampleBufferRef>();
  s = _vt.CMSampleBufferCreate(
      _vt.kCFAllocatorDefault,
      block,
      1, // dataReady
      ffi.nullptr.cast(),
      ffi.nullptr.cast(),
      dec.ref.fmtDesc,
      1,
      1,
      timing,
      1,
      sampleSize,
      samplePP);
  final sample = samplePP.value;
  pkgffi.calloc.free(timing);
  pkgffi.calloc.free(sampleSize);
  pkgffi.calloc.free(samplePP);
  _vt.CFRelease(block.cast());
  if (s != _noErr) return -6;

  final outFlags = pkgffi.calloc<ffi.UnsignedInt>();
  // PTS-as-pointer-value (see encoder for rationale).
  s = _vt.VTDecompressionSessionDecodeFrame(
      dec.ref.session, sample, 0, ffi.Pointer.fromAddress(ptsUs), outFlags);
  pkgffi.calloc.free(outFlags);
  _vt.CFRelease(sample.cast());
  if (s != _noErr) return -7;

  _vt.VTDecompressionSessionWaitForAsynchronousFrames(dec.ref.session);
  return 0;
}

// Plain equality for SPS/PPS change detection — not a MAC compare, so an
// early exit is fine (and cheaper than a constant-time scan).
bool _bytesEqual(
    ffi.Pointer<ffi.Uint8> a, ffi.Pointer<ffi.Uint8> b, int n) {
  for (int i = 0; i < n; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

ffi.Pointer<WvtDecodedFrame> wvtDecoderDrainOne(
    ffi.Pointer<WvtDecoder> dec) {
  if (dec == ffi.nullptr) return ffi.nullptr;
  while (true) {
    final node = _wvtDecQueuePop(dec.ref.queue);
    if (node == ffi.nullptr) return ffi.nullptr;
    final frame = _buildFrameFromNode(node);
    _wvtDecNodeFree(node);
    if (frame != ffi.nullptr) return frame;
    // Dropped/error frame — try the next.
  }
}

/// Convert a queued `WvtDecNode` (CVImageBuffer + PTS) into a Dart-owned
/// `WvtDecodedFrame` with packed I420 bytes. Returns `nullptr` for dropped
/// or errored frames.
ffi.Pointer<WvtDecodedFrame> _buildFrameFromNode(
    ffi.Pointer<WvtDecNode> node) {
  if (node.ref.status != _noErr || node.ref.img == ffi.nullptr) {
    return ffi.nullptr;
  }
  if ((node.ref.infoFlags & _kVTDecodeInfo_FrameDropped) != 0) {
    return ffi.nullptr;
  }
  final img = node.ref.img;
  if (_vt.CVPixelBufferLockBaseAddress(img, _kCVPixelBufferLock_ReadOnly) !=
      _kCVReturnSuccess) {
    return ffi.nullptr;
  }

  final fmt = _vt.CVPixelBufferGetPixelFormatType(img);
  if (fmt != kCVPixelFormatType_420YpCbCr8Planar &&
      fmt != kCVPixelFormatType_420YpCbCr8BiPlanarFullRange &&
      fmt != kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange) {
    _vt.CVPixelBufferUnlockBaseAddress(img, _kCVPixelBufferLock_ReadOnly);
    return ffi.nullptr;
  }

  final w = _vt.CVPixelBufferGetWidth(img);
  final h = _vt.CVPixelBufferGetHeight(img);
  final uvw = w >> 1;
  final uvh = h >> 1;
  final i420Size = w * h + uvw * uvh * 2;
  final data = pkgffi.malloc<ffi.Uint8>(i420Size);

  if (fmt == kCVPixelFormatType_420YpCbCr8Planar) {
    _copyPlane(data, w,
        _vt.CVPixelBufferGetBaseAddressOfPlane(img, 0).cast(),
        _vt.CVPixelBufferGetBytesPerRowOfPlane(img, 0), w, h);
    _copyPlane(data + w * h, uvw,
        _vt.CVPixelBufferGetBaseAddressOfPlane(img, 1).cast(),
        _vt.CVPixelBufferGetBytesPerRowOfPlane(img, 1), uvw, uvh);
    _copyPlane(data + w * h + uvw * uvh, uvw,
        _vt.CVPixelBufferGetBaseAddressOfPlane(img, 2).cast(),
        _vt.CVPixelBufferGetBytesPerRowOfPlane(img, 2), uvw, uvh);
  } else {
    // BiPlanar (NV12): Y plane + interleaved UV plane.
    _copyPlane(data, w,
        _vt.CVPixelBufferGetBaseAddressOfPlane(img, 0).cast(),
        _vt.CVPixelBufferGetBytesPerRowOfPlane(img, 0), w, h);
    final suv = _vt.CVPixelBufferGetBaseAddressOfPlane(img, 1).cast<ffi.Uint8>();
    final suvStride = _vt.CVPixelBufferGetBytesPerRowOfPlane(img, 1);
    final du = data + w * h;
    final dv = du + uvw * uvh;
    for (int r = 0; r < uvh; r++) {
      final row = suv + r * suvStride;
      for (int c = 0; c < uvw; c++) {
        du[r * uvw + c] = row[c * 2];
        dv[r * uvw + c] = row[c * 2 + 1];
      }
    }
  }
  _vt.CVPixelBufferUnlockBaseAddress(img, _kCVPixelBufferLock_ReadOnly);

  final frame = pkgffi.calloc<WvtDecodedFrame>();
  frame.ref.data = data;
  frame.ref.size = i420Size;
  frame.ref.width = w;
  frame.ref.height = h;
  frame.ref.ptsUs = node.ref.ptsUs;
  return frame;
}

int wvtDecodedFrameWidth(ffi.Pointer<WvtDecodedFrame> f) => f.ref.width;
int wvtDecodedFrameHeight(ffi.Pointer<WvtDecodedFrame> f) => f.ref.height;
int wvtDecodedFramePtsUs(ffi.Pointer<WvtDecodedFrame> f) => f.ref.ptsUs;
int wvtDecodedFrameSize(ffi.Pointer<WvtDecodedFrame> f) => f.ref.size;
ffi.Pointer<ffi.Uint8> wvtDecodedFrameData(
        ffi.Pointer<WvtDecodedFrame> f) =>
    f.ref.data;
void wvtDecodedFrameFree(ffi.Pointer<WvtDecodedFrame> f) {
  if (f == ffi.nullptr) return;
  if (f.ref.data != ffi.nullptr) pkgffi.malloc.free(f.ref.data);
  pkgffi.calloc.free(f);
}

void wvtDecoderDestroy(ffi.Pointer<WvtDecoder> dec) {
  if (dec == ffi.nullptr) return;
  if (dec.ref.session != ffi.nullptr) {
    _vt.VTDecompressionSessionInvalidate(dec.ref.session);
    _vt.CFRelease(dec.ref.session.cast());
  }
  if (dec.ref.fmtDesc != ffi.nullptr) {
    _vt.CFRelease(dec.ref.fmtDesc.cast());
  }
  if (dec.ref.sps != ffi.nullptr) pkgffi.malloc.free(dec.ref.sps);
  if (dec.ref.pps != ffi.nullptr) pkgffi.malloc.free(dec.ref.pps);
  if (dec.ref.cbRecord != ffi.nullptr) {
    pkgffi.calloc.free(dec.ref.cbRecord);
  }
  if (dec.ref.queue != ffi.nullptr) {
    _wvtDecQueueRelease(dec.ref.queue);
  }
  pkgffi.calloc.free(dec);
}
