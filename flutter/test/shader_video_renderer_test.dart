import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:webdartc/webdartc.dart';
import 'package:webdartc_flutter/webdartc_flutter.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('webdartc_flutter/render');
  final calls = <MethodCall>[];

  setUp(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      switch (call.method) {
        case 'create':
          return 42;
        case 'render':
        case 'dispose':
          return null;
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('create → textureId resolves', () async {
    final r = ShaderVideoRenderer();
    expect(await r.textureId, 42);
    expect(calls.single.method, 'create');
  });

  test('render forwards width/height/data with correct textureId', () async {
    final r = ShaderVideoRenderer();
    await r.textureId;
    final frame = VideoFrame(
      format: VideoPixelFormat.i420,
      codedWidth: 160,
      codedHeight: 120,
      timestamp: 0,
      data: Uint8List(160 * 120 * 3 ~/ 2),
    );
    r.render(frame);
    await Future<void>.delayed(Duration.zero);
    final renderCall = calls.firstWhere((c) => c.method == 'render');
    final args = renderCall.arguments as Map<Object?, Object?>;
    expect(args['textureId'], 42);
    expect(args['width'], 160);
    expect(args['height'], 120);
    expect(args['data'], isA<Uint8List>());
    expect((args['data'] as Uint8List).length, 160 * 120 * 3 ~/ 2);
  });

  test('dispose sends dispose method with textureId', () async {
    final r = ShaderVideoRenderer();
    await r.textureId;
    await r.dispose();
    final disposeCall = calls.firstWhere((c) => c.method == 'dispose');
    expect((disposeCall.arguments as Map)['textureId'], 42);
  });

  test('render is throttled while a previous render is in flight', () async {
    // The mock handler returns synchronously within the event loop, but
    // the renderer uses invokeMethod which is async. Flooding render()
    // must coalesce to at most one pending call at a time.
    final r = ShaderVideoRenderer();
    await r.textureId;
    final frame = VideoFrame(
      format: VideoPixelFormat.i420,
      codedWidth: 8,
      codedHeight: 8,
      timestamp: 0,
      data: Uint8List(8 * 8 * 3 ~/ 2),
    );
    for (var i = 0; i < 10; i++) {
      r.render(frame);
    }
    await Future<void>.delayed(Duration.zero);
    final renderCount = calls.where((c) => c.method == 'render').length;
    expect(renderCount, lessThan(10),
        reason: 'flooded renders should be coalesced');
  });

  test('render ignores non-I420 frames', () async {
    final r = ShaderVideoRenderer();
    await r.textureId;
    final nv12 = VideoFrame(
      format: VideoPixelFormat.nv12,
      codedWidth: 8,
      codedHeight: 8,
      timestamp: 0,
      data: Uint8List(8 * 8 * 3 ~/ 2),
    );
    r.render(nv12);
    await Future<void>.delayed(Duration.zero);
    expect(calls.where((c) => c.method == 'render'), isEmpty);
  });
}
