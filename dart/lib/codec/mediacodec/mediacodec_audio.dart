/// Android MediaCodec Opus encoder/decoder helper (Android only).
///
/// Pure-Dart FFI over the NDK `libmediandk.so`, driven through the synchronous
/// buffer API — the same shape as `mediacodec_video.dart`, but for audio: s16
/// interleaved PCM in / Opus packets out (encoder) and the reverse (decoder).
///
/// The decoder needs the three Opus codec-specific-data buffers that a container
/// (Ogg/MP4) would normally carry: `csd-0` (the 19-byte OpusHead), `csd-1`
/// (codec delay, ns) and `csd-2` (seek preroll, ns). WebRTC has no container, so
/// we synthesise a standard OpusHead from the sample rate / channel count.
library;

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkgffi;

import 'bindings.g.dart';
import 'mediacodec_lib.dart';
import 'mime_types.dart';

// AMediaFormat keys the generated bindings don't expose as symbols. These are
// stable `AMEDIAFORMAT_KEY_*` string values (NdkMediaFormat.h) — safe to pass
// straight to the setters, which take a `const char* name`.
const String _keySampleRate = 'sample-rate';
const String _keyChannelCount = 'channel-count';
const String _keyCsd0 = 'csd-0';
const String _keyCsd1 = 'csd-1';
const String _keyCsd2 = 'csd-2';

// Standard Opus pre-skip (48 kHz reference encoder): 3840 samples = 80 ms.
const int _preSkipSamples = 3840;
const int _codecDelayNs = _preSkipSamples * 1000000000 ~/ 48000; // 80 ms
const int _seekPrerollNs = 80000000; // 80 ms

/// The 19-byte OpusHead identification header (RFC 7845 §5.1) the Android Opus
/// decoder wants as `csd-0`. `inputSampleRate` is informational (the original
/// rate); decode always runs at 48 kHz internally.
Uint8List _opusHead(int channels, int inputSampleRate) {
  final b = ByteData(19);
  for (var i = 0; i < 8; i++) {
    b.setUint8(i, 'OpusHead'.codeUnitAt(i));
  }
  b.setUint8(8, 1); // version
  b.setUint8(9, channels);
  b.setUint16(10, _preSkipSamples, Endian.little);
  b.setUint32(12, inputSampleRate, Endian.little);
  b.setUint16(16, 0, Endian.little); // output gain
  b.setUint8(18, 0); // channel mapping family 0 (mono/stereo)
  return b.buffer.asUint8List();
}

Uint8List _int64le(int v) {
  final d = ByteData(8)..setInt64(0, v, Endian.little);
  return d.buffer.asUint8List();
}

/// Sets a byte-buffer format key from Dart bytes (copied into native memory that
/// AMediaFormat retains for the format's lifetime).
void _setBuffer(ffi.Pointer<AMediaFormat> fmt, String key, Uint8List bytes) {
  final name = mediaCodecUtf8(key);
  final buf = pkgffi.malloc<ffi.Uint8>(bytes.length);
  buf.asTypedList(bytes.length).setAll(0, bytes);
  mediaCodecLib.AMediaFormat_setBuffer(
      fmt, name, buf.cast<ffi.Void>(), bytes.length);
  pkgffi.malloc.free(name);
  pkgffi.malloc.free(buf);
}

void _setInt(ffi.Pointer<AMediaFormat> fmt, String key, int value) {
  final name = mediaCodecUtf8(key);
  mediaCodecLib.AMediaFormat_setInt32(fmt, name, value);
  pkgffi.malloc.free(name);
}

/// One encoded Opus packet + the presentation timestamp MediaCodec carried
/// through from its input frame (pipeline latency means a packet drained now may
/// belong to an earlier `encode` call, so the PTS travels with the bytes).
final class EncodedOpusPacket {
  final Uint8List data;
  final int ptsUs;
  const EncodedOpusPacket(this.data, this.ptsUs);
}

// ── Encoder ─────────────────────────────────────────────────────────────────

/// Encodes s16 interleaved PCM (one 20 ms frame per `encode` call) to Opus.
final class MediaCodecOpusEncoder {
  final ffi.Pointer<AMediaCodec> _codec;

  final ffi.Pointer<ffi.Size> _sizePtr = pkgffi.calloc<ffi.Size>();
  final ffi.Pointer<AMediaCodecBufferInfo> _info =
      pkgffi.calloc<AMediaCodecBufferInfo>();

  MediaCodecOpusEncoder._(this._codec);

  static MediaCodecOpusEncoder create(
      int sampleRate, int channels, int bitrate) {
    final mime = mediaCodecUtf8(opusMime);
    final codec = mediaCodecLib.AMediaCodec_createEncoderByType(mime);
    pkgffi.malloc.free(mime);
    if (codec == ffi.nullptr) {
      throw StateError('AMediaCodec_createEncoderByType(audio/opus) null');
    }
    final fmt = mediaCodecLib.AMediaFormat_new();
    final m2 = mediaCodecUtf8(opusMime);
    mediaCodecLib.AMediaFormat_setString(
        fmt, mediaCodecLib.AMEDIAFORMAT_KEY_MIME, m2);
    pkgffi.malloc.free(m2);
    _setInt(fmt, _keySampleRate, sampleRate);
    _setInt(fmt, _keyChannelCount, channels);
    mediaCodecLib.AMediaFormat_setInt32(
        fmt, mediaCodecLib.AMEDIAFORMAT_KEY_BIT_RATE, bitrate);
    final cfg = mediaCodecLib.AMediaCodec_configure(
        codec, fmt, ffi.nullptr, ffi.nullptr, configureFlagEncode);
    mediaCodecLib.AMediaFormat_delete(fmt);
    if (!mediaCodecOk(cfg)) {
      mediaCodecLib.AMediaCodec_delete(codec);
      throw StateError('AMediaCodec_configure (opus encoder) failed: $cfg');
    }
    if (!mediaCodecOk(mediaCodecLib.AMediaCodec_start(codec))) {
      mediaCodecLib.AMediaCodec_delete(codec);
      throw StateError('AMediaCodec_start (opus encoder) failed');
    }
    return MediaCodecOpusEncoder._(codec);
  }

  /// Feeds one PCM frame (s16 interleaved bytes) and returns any Opus packets
  /// now available.
  List<EncodedOpusPacket> encode(Uint8List pcm, int ptsUs) {
    final idx = mediaCodecLib.AMediaCodec_dequeueInputBuffer(
        _codec, inputTimeoutUs);
    if (idx < 0) return const [];
    final buf = mediaCodecLib.AMediaCodec_getInputBuffer(_codec, idx, _sizePtr);
    if (buf == ffi.nullptr || _sizePtr.value < pcm.length) {
      mediaCodecLib.AMediaCodec_queueInputBuffer(_codec, idx, 0, 0, ptsUs, 0);
      return const [];
    }
    buf.asTypedList(pcm.length).setAll(0, pcm);
    mediaCodecLib.AMediaCodec_queueInputBuffer(
        _codec, idx, 0, pcm.length, ptsUs, 0);
    return _drain();
  }

  List<EncodedOpusPacket> _drain() {
    final out = <EncodedOpusPacket>[];
    while (true) {
      final idx = mediaCodecLib.AMediaCodec_dequeueOutputBuffer(
          _codec, _info, outputTimeoutUs);
      if (idx == infoTryAgainLater) break;
      if (idx < 0) continue;
      final off = _info.ref.offset;
      final len = _info.ref.size;
      final flags = _info.ref.flags;
      final pts = _info.ref.presentationTimeUs;
      if (len > 0 && (flags & bufferFlagCodecConfig) == 0) {
        final b = mediaCodecLib.AMediaCodec_getOutputBuffer(
            _codec, idx, _sizePtr);
        if (b != ffi.nullptr) {
          out.add(EncodedOpusPacket(
              b.asTypedList(off + len).sublist(off, off + len), pts));
        }
      }
      mediaCodecLib.AMediaCodec_releaseOutputBuffer(_codec, idx, false);
    }
    return out;
  }

  void close() {
    mediaCodecLib.AMediaCodec_stop(_codec);
    mediaCodecLib.AMediaCodec_delete(_codec);
    pkgffi.calloc.free(_sizePtr);
    pkgffi.calloc.free(_info);
  }
}

// ── Decoder ─────────────────────────────────────────────────────────────────

/// One decoded PCM chunk: s16 interleaved samples + the input PTS.
final class DecodedPcm {
  final Uint8List data; // s16 interleaved
  final int ptsUs;
  const DecodedPcm(this.data, this.ptsUs);
}

/// Decodes Opus packets to s16 interleaved PCM.
final class MediaCodecOpusDecoder {
  final ffi.Pointer<AMediaCodec> _codec;

  final ffi.Pointer<ffi.Size> _sizePtr = pkgffi.calloc<ffi.Size>();
  final ffi.Pointer<AMediaCodecBufferInfo> _info =
      pkgffi.calloc<AMediaCodecBufferInfo>();

  MediaCodecOpusDecoder._(this._codec);

  static MediaCodecOpusDecoder create(int sampleRate, int channels) {
    final mime = mediaCodecUtf8(opusMime);
    final codec = mediaCodecLib.AMediaCodec_createDecoderByType(mime);
    pkgffi.malloc.free(mime);
    if (codec == ffi.nullptr) {
      throw StateError('AMediaCodec_createDecoderByType(audio/opus) null');
    }
    final fmt = mediaCodecLib.AMediaFormat_new();
    final m2 = mediaCodecUtf8(opusMime);
    mediaCodecLib.AMediaFormat_setString(
        fmt, mediaCodecLib.AMEDIAFORMAT_KEY_MIME, m2);
    pkgffi.malloc.free(m2);
    _setInt(fmt, _keySampleRate, sampleRate);
    _setInt(fmt, _keyChannelCount, channels);
    // The container-supplied Opus setup data, synthesised for WebRTC.
    _setBuffer(fmt, _keyCsd0, _opusHead(channels, sampleRate));
    _setBuffer(fmt, _keyCsd1, _int64le(_codecDelayNs));
    _setBuffer(fmt, _keyCsd2, _int64le(_seekPrerollNs));
    final cfg = mediaCodecLib.AMediaCodec_configure(
        codec, fmt, ffi.nullptr, ffi.nullptr, 0);
    mediaCodecLib.AMediaFormat_delete(fmt);
    if (!mediaCodecOk(cfg)) {
      mediaCodecLib.AMediaCodec_delete(codec);
      throw StateError('AMediaCodec_configure (opus decoder) failed: $cfg');
    }
    if (!mediaCodecOk(mediaCodecLib.AMediaCodec_start(codec))) {
      mediaCodecLib.AMediaCodec_delete(codec);
      throw StateError('AMediaCodec_start (opus decoder) failed');
    }
    return MediaCodecOpusDecoder._(codec);
  }

  List<DecodedPcm> decode(Uint8List opus, int ptsUs) {
    final idx = mediaCodecLib.AMediaCodec_dequeueInputBuffer(
        _codec, inputTimeoutUs);
    if (idx >= 0) {
      final buf =
          mediaCodecLib.AMediaCodec_getInputBuffer(_codec, idx, _sizePtr);
      if (buf != ffi.nullptr && _sizePtr.value >= opus.length) {
        buf.asTypedList(opus.length).setAll(0, opus);
        mediaCodecLib.AMediaCodec_queueInputBuffer(
            _codec, idx, 0, opus.length, ptsUs, 0);
      } else {
        mediaCodecLib.AMediaCodec_queueInputBuffer(_codec, idx, 0, 0, ptsUs, 0);
      }
    }
    return _drain();
  }

  List<DecodedPcm> _drain() {
    final out = <DecodedPcm>[];
    while (true) {
      final idx = mediaCodecLib.AMediaCodec_dequeueOutputBuffer(
          _codec, _info, outputTimeoutUs);
      if (idx == infoTryAgainLater) break;
      if (idx < 0) continue; // FORMAT/BUFFERS changed
      final off = _info.ref.offset;
      final len = _info.ref.size;
      final flags = _info.ref.flags;
      final pts = _info.ref.presentationTimeUs;
      if (len > 0 && (flags & bufferFlagCodecConfig) == 0) {
        final b = mediaCodecLib.AMediaCodec_getOutputBuffer(
            _codec, idx, _sizePtr);
        if (b != ffi.nullptr) {
          out.add(DecodedPcm(
              b.asTypedList(off + len).sublist(off, off + len), pts));
        }
      }
      mediaCodecLib.AMediaCodec_releaseOutputBuffer(_codec, idx, false);
    }
    return out;
  }

  void close() {
    mediaCodecLib.AMediaCodec_stop(_codec);
    mediaCodecLib.AMediaCodec_delete(_codec);
    pkgffi.calloc.free(_sizePtr);
    pkgffi.calloc.free(_info);
  }
}
