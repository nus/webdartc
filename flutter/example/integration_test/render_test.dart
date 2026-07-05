// On-device test for the webdartc_flutter render plugin.
//
// This is the one piece with no equivalent under dart/test/ — it's Flutter
// plugin code (the SurfaceTexture / MethodChannel renderer). Everything else
// validated on-device (crypto, codecs, transport) is the Dart package's own
// suite, run via dart_suite_test.dart.
//
// Run:  cd flutter/example && flutter test integration_test/render_test.dart -d <device>
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'package:webdartc/webdartc.dart';
import 'package:webdartc_flutter/webdartc_flutter.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('render plugin: create → render frames → dispose',
      (tester) async {
    const width = 320, height = 240, frames = 15;
    final renderer = ShaderVideoRenderer();
    final id = await renderer.textureId; // resolves only if `create` succeeded
    expect(id, greaterThanOrEqualTo(0));

    await tester.pumpWidget(MaterialApp(
      home: Center(child: VideoRendererWidget(renderer: renderer)),
    ));

    final src = FakeVideoSource(width: width, height: height, framerate: 30);
    for (var i = 0; i < frames; i++) {
      renderer.render(src.frameAt(i * 33333));
      await tester.pump(const Duration(milliseconds: 16));
    }
    await renderer.dispose();
  });
}
