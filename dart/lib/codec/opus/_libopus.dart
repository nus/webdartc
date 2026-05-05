/// Internal libopus binding entry point shared by encoder and decoder.
library;

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;

import 'opus_bindings.g.dart' as op;

ffi.DynamicLibrary _open() {
  // macOS: brew prefix is /opt/homebrew on Apple Silicon and /usr/local on
  // Intel; neither is in dyld's default search path, so absolute fallbacks
  // are required for FFI to find libopus.
  final candidates = Platform.isMacOS
      ? const [
          'libopus.dylib',
          'libopus.0.dylib',
          '/opt/homebrew/lib/libopus.dylib',
          '/opt/homebrew/lib/libopus.0.dylib',
          '/usr/local/lib/libopus.dylib',
          '/usr/local/lib/libopus.0.dylib',
        ]
      : Platform.isWindows
          ? const ['opus.dll', 'libopus-0.dll']
          : const ['libopus.so.0', 'libopus.so'];
  Object? lastError;
  for (final name in candidates) {
    try {
      return ffi.DynamicLibrary.open(name);
    } catch (e) {
      lastError = e;
    }
  }
  throw StateError('Could not load libopus ($candidates): $lastError');
}

final ffi.DynamicLibrary _dylib = _open();
final op.OpusBindings libopus = op.OpusBindings(_dylib);

/// `opus_encoder_ctl(st, request, value)` — variadic-stripped 3-arg form for
/// integer-valued CTL requests (bitrate, complexity, etc.). The ffigen
/// binding only exposes the 2-arg form, so look up the symbol manually.
typedef _OpusEncCtlIntNative = ffi.Int Function(
    ffi.Pointer<op.OpusEncoder>, ffi.Int32, ffi.Int32);
typedef OpusEncCtlIntDart = int Function(
    ffi.Pointer<op.OpusEncoder>, int, int);
final OpusEncCtlIntDart opusEncoderCtlInt = _dylib
    .lookup<ffi.NativeFunction<_OpusEncCtlIntNative>>('opus_encoder_ctl')
    .asFunction<OpusEncCtlIntDart>();
