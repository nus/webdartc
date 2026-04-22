/// Shader-based video renderer — sends I420 bytes to the native plugin,
/// which wraps them as an NV12 `CVPixelBuffer` that Flutter's Metal (or
/// GL) compositor samples via its built-in YUV→RGB shader.
///
/// macOS is the only platform currently wired. iOS / Linux / Windows will
/// follow the same shape.
library;

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:webdartc/webdartc.dart';

import 'video_renderer.dart';

const _channel = MethodChannel('webdartc_flutter/render');

final class ShaderVideoRenderer implements VideoRenderer {
  final Completer<int> _idCompleter = Completer<int>();
  int? _textureId;
  bool _disposed = false;
  bool _inFlight = false;

  ShaderVideoRenderer() {
    _create();
  }

  Future<void> _create() async {
    try {
      final id = await _channel.invokeMethod<int>('create');
      if (id == null) {
        _idCompleter.completeError(
            StateError('native create returned null'));
        return;
      }
      _textureId = id;
      _idCompleter.complete(id);
    } catch (e, st) {
      _idCompleter.completeError(e, st);
    }
  }

  @override
  Future<int> get textureId => _idCompleter.future;

  @override
  void render(VideoFrame frame) {
    if (_disposed || _textureId == null || _inFlight) return;
    if (frame.format != VideoPixelFormat.i420) return;
    _inFlight = true;
    _channel.invokeMethod<void>('render', {
      'textureId': _textureId,
      'width': frame.codedWidth,
      'height': frame.codedHeight,
      'data': frame.data,
    }).whenComplete(() => _inFlight = false);
  }

  @override
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    final id = _textureId;
    if (id == null) return;
    await _channel.invokeMethod<void>('dispose', {'textureId': id});
  }
}
