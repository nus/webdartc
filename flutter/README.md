# webdartc_flutter

Flutter integration for [webdartc](../dart) — renders decoded video frames, bridges platform capture/playback.

## Status

| Surface | macOS | iOS | Linux | Windows | Android |
|---------|-------|-----|-------|---------|---------|
| Video renderer | ✅ Metal (`ShaderVideoRenderer`) | roadmap | ✅ FlPixelBufferTexture (CPU I420 → RGBA8) | ✅ PixelBufferTexture (CPU I420 → BGRA8) | ✅ SurfaceTexture (CPU I420 → ARGB) |
| Camera capture | roadmap | roadmap | roadmap | roadmap | roadmap |
| Mic / speaker | roadmap | roadmap | roadmap | roadmap | roadmap |

## Renderer

`ShaderVideoRenderer` takes CPU I420 frames (produced by `webdartc`'s `VideoDecoder`) and presents them through a Flutter `Texture`. On **macOS** the plugin wraps each frame as an **NV12 `CVPixelBuffer`** — Flutter's Metal compositor samples it with its built-in YUV→RGB shader, so no custom shader code lives in this package. On **Windows**, `flutter::PixelBufferTexture` is BGRA8-only, so the plugin runs a small BT.601 full-range integer I420 → BGRA8 conversion in C++ before handing the buffer back to Flutter. On **Android**, the Kotlin plugin runs the same BT.601 I420 → ARGB conversion and posts it to a `SurfaceTexture` via `Surface.lockCanvas`. On **Linux**, the GTK plugin runs the same BT.601 conversion to RGBA8 and returns it from an `FlPixelBufferTexture`, which Flutter's GLES compositor uploads as a `GL_RGBA` texture. GPU paths — a `GpuSurfaceTexture` HLSL shader on Windows, and zero-copy `MediaCodec` output Surface / GLES YUV→RGB on Android — are filed in the backlog as follow-ups.

```dart
import 'package:webdartc/webdartc.dart';
import 'package:webdartc_flutter/webdartc_flutter.dart';

final renderer = ShaderVideoRenderer();
final decoder = VideoDecoder(
  output: (frame) { renderer.render(frame); frame.close(); },
  error: (e) => print('decode error: $e'),
);
decoder.configure(const VideoDecoderConfig(codec: 'h264'));
// feed decoder.decode(chunk) from your RTP pipeline

// In the widget tree:
VideoRendererWidget(renderer: renderer)
```

## Example

A runnable macOS / Android demo acting as a full WebRTC peer against a browser
(Flutter ↔ browser bidirectional video over real DTLS/SRTP/ICE) lives
at [`example/`](example). It shows `local` (FakeVideoSource preview) and
`remote` (decoded browser camera) tiles side-by-side. macOS negotiates H.264;
Android negotiates VP8 (no Android H.264 backend yet).

```bash
# Terminal 1 — from dart/: signaling + static HTTP server
dart run example/signaling/server.dart --port=8080

# Terminal 2 — open http://127.0.0.1:8080/ in Chrome

# Terminal 3 — from flutter/example/:
flutter run -d macos        # or: flutter run -d <android-device>
```

Prereqs: Xcode, CocoaPods (`brew install cocoapods`).

## Tests

```bash
flutter test        # widget tests (mock MethodChannel; works on any host)
flutter analyze
```
