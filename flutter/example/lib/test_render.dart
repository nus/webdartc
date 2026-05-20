/// Renders a `FakeVideoSource` through `ShaderVideoRenderer` without any
/// networking or codecs — operational check for the native plugin path.
///
/// ```
/// cd flutter/example
/// flutter run -d windows -t lib/test_render.dart
/// ```
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:webdartc/webdartc.dart';
import 'package:webdartc_flutter/webdartc_flutter.dart';

void main() => runApp(const _App());

class _App extends StatelessWidget {
  const _App();
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'webdartc_flutter render-only test',
        theme: ThemeData.dark(),
        home: const _Demo(),
      );
}

class _Demo extends StatefulWidget {
  const _Demo();
  @override
  State<_Demo> createState() => _DemoState();
}

class _DemoState extends State<_Demo> {
  static const _width = 320;
  static const _height = 240;
  static const _fps = 30.0;

  late final ShaderVideoRenderer _renderer;
  StreamSubscription<VideoFrame>? _sub;
  int _frameCount = 0;

  @override
  void initState() {
    super.initState();
    _renderer = ShaderVideoRenderer();
    _start();
  }

  Future<void> _start() async {
    await _renderer.textureId;
    final source = FakeVideoSource(
      width: _width,
      height: _height,
      framerate: _fps,
    );
    _sub = source.start().listen((frame) {
      _renderer.render(frame);
      _frameCount++;
      if (_frameCount % 30 == 0) {
        if (mounted) setState(() {});
      }
    });
  }

  @override
  void dispose() {
    _sub?.cancel();
    _renderer.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('render-only test')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            SizedBox(
              width: _width.toDouble(),
              height: _height.toDouble(),
              child: VideoRendererWidget(renderer: _renderer),
            ),
            const SizedBox(height: 16),
            Text('frames rendered: $_frameCount'),
          ],
        ),
      ),
    );
  }
}
