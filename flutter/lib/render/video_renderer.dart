/// Video renderer abstraction for webdartc.
///
/// Takes decoded [VideoFrame]s (CPU I420) and presents them via a Flutter
/// [Texture]. Platform-specific implementations live in sibling files —
/// macOS uses [ShaderVideoRenderer] which hands frames to the native
/// plugin as an NV12 `CVPixelBuffer`.
library;

import 'package:webdartc/webdartc.dart';

/// Sink for decoded frames bound to a Flutter texture.
///
/// Lifecycle:
/// 1. Construct → wait for [textureId] to resolve.
/// 2. Wrap [textureId] in a `Texture` widget (or `VideoRendererWidget`).
/// 3. Feed each decoded [VideoFrame] into [render]. The frame may be
///    closed immediately after; the renderer copies what it needs.
/// 4. Call [dispose] when the widget is removed.
abstract interface class VideoRenderer {
  /// Resolves once the platform texture has been registered with the
  /// Flutter engine.
  Future<int> get textureId;

  /// Push a decoded [VideoFrame] for display. Safe to call at any rate;
  /// the implementation deduplicates to the display's refresh.
  void render(VideoFrame frame);

  /// Release the underlying platform texture.
  Future<void> dispose();
}
