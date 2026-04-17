/// H.264 video encoder backend powered by Cisco's OpenH264.
///
/// Registers with [CodecRegistry] via [registerH264Codec]. Implements
/// [VideoEncoderBackend] so the generic W3C-style [VideoEncoder] front-end
/// can drive it.
library;

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import '../../media/video_frame.dart';
import '../codec_registry.dart';
import '../video_codec.dart';
import 'openh264_bindings.g.dart' as oh;

ffi.DynamicLibrary _openLibOpenH264() {
  final candidates = Platform.isMacOS
      ? const ['libopenh264.dylib', 'libopenh264.7.dylib']
      : Platform.isWindows
          ? const ['openh264.dll']
          : const ['libopenh264.so.7', 'libopenh264.so'];
  Object? lastError;
  for (final name in candidates) {
    try {
      return ffi.DynamicLibrary.open(name);
    } catch (e) {
      lastError = e;
    }
  }
  throw StateError('Could not load libopenh264 ($candidates): $lastError');
}

final oh.OpenH264Bindings _lib = oh.OpenH264Bindings(_openLibOpenH264());

/// Registers the H.264 encoder backend under the codec key `h264`.
void registerH264Codec() {
  CodecRegistry.registerVideoEncoder('h264', H264EncoderBackend.new);
}

/// H.264 encoder backend wrapping OpenH264's ISVCEncoder via its C vtable.
final class H264EncoderBackend implements VideoEncoderBackend {
  ffi.Pointer<oh.ISVCEncoder>? _encoder;
  VideoDecoderConfig? _decoderConfig;

  void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?)? _onOutput;
  void Function(Object)? _onError;

  int _width = 0;
  int _height = 0;

  @override
  set onOutput(void Function(EncodedVideoChunk, EncodedVideoChunkMetadata?) cb) =>
      _onOutput = cb;

  @override
  set onError(void Function(Object) cb) => _onError = cb;

  @override
  void configure(VideoEncoderConfig config) {
    _width = config.width;
    _height = config.height;
    final fps = (config.framerate ?? 30).toDouble();
    final bitrate = config.bitrate ?? 400000;

    // slot: Pointer<ISVCEncoder> = Pointer<Pointer<ISVCEncoderVtbl>>.
    // WelsCreateSVCEncoder takes Pointer<Pointer<ISVCEncoder>> = address of slot.
    final ppEnc = pkgffi.calloc<ffi.Pointer<oh.ISVCEncoder>>();
    final createRes = _lib.WelsCreateSVCEncoder(ppEnc);
    if (createRes != 0 || ppEnc.value == ffi.nullptr) {
      pkgffi.calloc.free(ppEnc);
      throw StateError('WelsCreateSVCEncoder failed: $createRes');
    }
    final handle = ppEnc.value; // Pointer<ISVCEncoder> = Pointer<Pointer<Vtbl>>
    pkgffi.calloc.free(ppEnc); // slot no longer needed; handle is owned by OpenH264.
    final vtbl = handle.value.ref;

    final param = pkgffi.calloc<oh.SEncParamBase>();
    param.ref.iUsageTypeAsInt =
        oh.EUsageType.CAMERA_VIDEO_REAL_TIME.value;
    param.ref.iPicWidth = _width;
    param.ref.iPicHeight = _height;
    param.ref.iTargetBitrate = bitrate;
    param.ref.iRCModeAsInt = oh.RC_MODES.RC_BITRATE_MODE.value;
    param.ref.fMaxFrameRate = fps;

    final init = vtbl.Initialize.asFunction<
        int Function(
          ffi.Pointer<oh.ISVCEncoder>,
          ffi.Pointer<oh.SEncParamBase>,
        )>();
    final initRes = init(handle, param);
    pkgffi.calloc.free(param);
    if (initRes != 0) {
      _lib.WelsDestroySVCEncoder(handle);
      throw StateError('ISVCEncoder.Initialize failed: $initRes');
    }

    _encoder = handle;
    _decoderConfig = VideoDecoderConfig(
      codec: 'h264',
      codedWidth: _width,
      codedHeight: _height,
    );
  }

  @override
  void encode(VideoFrame frame, {bool keyFrame = false}) {
    final encoder = _encoder;
    if (encoder == null) {
      _onError?.call(StateError('Encoder not configured'));
      return;
    }
    if (frame.format != VideoPixelFormat.i420) {
      _onError?.call(StateError('H.264 encoder requires I420 input'));
      return;
    }
    if (frame.codedWidth != _width || frame.codedHeight != _height) {
      _onError?.call(StateError(
          'Frame size mismatch: expected ${_width}x$_height, got ${frame.codedWidth}x${frame.codedHeight}'));
      return;
    }

    final vtbl = encoder.value.ref;

    if (keyFrame) {
      final forceIdr = vtbl.ForceIntraFrame.asFunction<
          int Function(
            ffi.Pointer<oh.ISVCEncoder>,
            bool,
          )>();
      forceIdr(encoder, true);
    }

    // Copy I420 data into a single native buffer, then set plane pointers.
    final totalSize = frame.data.length;
    final native = pkgffi.calloc<ffi.UnsignedChar>(totalSize);
    native.cast<ffi.Uint8>().asTypedList(totalSize).setAll(0, frame.data);

    final pic = pkgffi.calloc<oh.SSourcePicture>();
    final ySize = _width * _height;
    final uvStride = _width >> 1;
    final uvSize = uvStride * (_height >> 1);
    pic.ref.iColorFormat = oh.EVideoFormatType.videoFormatI420.value;
    pic.ref.iPicWidth = _width;
    pic.ref.iPicHeight = _height;
    pic.ref.iStride[0] = _width;
    pic.ref.iStride[1] = uvStride;
    pic.ref.iStride[2] = uvStride;
    pic.ref.iStride[3] = 0;
    pic.ref.pData[0] = native;
    pic.ref.pData[1] = (native + ySize).cast();
    pic.ref.pData[2] = (native + (ySize + uvSize)).cast();
    pic.ref.pData[3] = ffi.nullptr;
    pic.ref.uiTimeStamp = frame.timestamp ~/ 1000;

    final bsInfo = pkgffi.calloc<oh.SFrameBSInfo>();

    final encodeFn = vtbl.EncodeFrame.asFunction<
        int Function(
          ffi.Pointer<oh.ISVCEncoder>,
          ffi.Pointer<oh.SSourcePicture>,
          ffi.Pointer<oh.SFrameBSInfo>,
        )>();
    final encodeRes = encodeFn(encoder, pic, bsInfo);

    try {
      if (encodeRes != 0) {
        _onError?.call(StateError('EncodeFrame failed: $encodeRes'));
        return;
      }
      _emitBitstream(bsInfo.ref, frame.timestamp);
    } finally {
      pkgffi.calloc.free(bsInfo);
      pkgffi.calloc.free(pic);
      pkgffi.calloc.free(native);
    }
  }

  void _emitBitstream(oh.SFrameBSInfo info, int timestamp) {
    // Skip when encoder produced no output (e.g. skipped frame).
    final frameType = info.eFrameType;
    if (frameType == oh.EVideoFrameType.videoFrameTypeSkip ||
        frameType == oh.EVideoFrameType.videoFrameTypeInvalid) {
      return;
    }
    if (info.iFrameSizeInBytes <= 0) return;

    // Sum sizes across all layers to allocate a single contiguous Annex B buffer.
    var total = 0;
    for (var l = 0; l < info.iLayerNum; l++) {
      final layer = info.sLayerInfo[l];
      for (var n = 0; n < layer.iNalCount; n++) {
        total += layer.pNalLengthInByte[n];
      }
    }
    final out = Uint8List(total);
    var w = 0;
    for (var l = 0; l < info.iLayerNum; l++) {
      final layer = info.sLayerInfo[l];
      var layerOffset = 0;
      for (var n = 0; n < layer.iNalCount; n++) {
        final nalLen = layer.pNalLengthInByte[n];
        final src = (layer.pBsBuf + layerOffset).cast<ffi.Uint8>()
            .asTypedList(nalLen);
        out.setRange(w, w + nalLen, src);
        w += nalLen;
        layerOffset += nalLen;
      }
    }

    final isKey = frameType == oh.EVideoFrameType.videoFrameTypeIDR ||
        frameType == oh.EVideoFrameType.videoFrameTypeI;
    _onOutput?.call(
      EncodedVideoChunk(
        type: isKey ? EncodedVideoChunkType.key : EncodedVideoChunkType.delta,
        timestamp: timestamp,
        data: out,
      ),
      isKey
          ? EncodedVideoChunkMetadata(decoderConfig: _decoderConfig)
          : null,
    );
  }

  @override
  Future<void> flush() async {
    // OpenH264 real-time encoder produces output synchronously; nothing buffered.
  }

  @override
  void reset() => close();

  @override
  void close() {
    final encoder = _encoder;
    if (encoder != null) {
      final vtbl = encoder.value.ref;
      final uninit = vtbl.Uninitialize.asFunction<
          int Function(ffi.Pointer<oh.ISVCEncoder>)>();
      uninit(encoder);
      _lib.WelsDestroySVCEncoder(encoder);
      _encoder = null;
    }
  }
}
