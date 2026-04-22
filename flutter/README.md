# webdartc_flutter

Flutter integration for [webdartc](../dart) — renders decoded video frames, bridges platform capture/playback.

## Status

| Surface | macOS | iOS | Linux | Windows | Android |
|---------|-------|-----|-------|---------|---------|
| Video renderer | ✅ Metal (`ShaderVideoRenderer`) | roadmap | roadmap (GLES) | roadmap | roadmap |
| Camera capture | roadmap | roadmap | roadmap | roadmap | roadmap |
| Mic / speaker | roadmap | roadmap | roadmap | roadmap | roadmap |

## Renderer

`ShaderVideoRenderer` takes CPU I420 frames (produced by `webdartc`'s `VideoDecoder`) and presents them through a Flutter `Texture`. On macOS the plugin wraps each frame as an **NV12 `CVPixelBuffer`** — Flutter's Metal compositor samples it with its built-in YUV→RGB shader, so no custom shader code lives in this package.

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

A runnable macOS demo acting as a full WebRTC peer against a browser
(Flutter ↔ browser bidirectional H.264 video over real DTLS/SRTP/ICE) lives
at [`example/`](example). It shows `local` (FakeVideoSource preview) and
`remote` (decoded browser camera) tiles side-by-side.

```bash
# Terminal 1 — from dart/: signaling + static HTTP server
dart run example/video_call/bin/server.dart --port=8080

# Terminal 2 — open http://127.0.0.1:8080/?bidir=1 in Chrome

# Terminal 3 — from flutter/example/:
flutter run -d macos
```

Prereqs: Xcode, CocoaPods (`brew install cocoapods`).

## Tests

```bash
flutter test        # widget tests (mock MethodChannel; works on any host)
flutter analyze
```
