// Build hook: compiles the VideoToolbox C helper on macOS/iOS.
//
// On other operating systems the hook is a no-op — the VideoToolbox
// backend is macOS/iOS-only and the helper is only needed there.
//
// Docs: https://dart.dev/tools/hooks

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final targetOS = input.config.code.targetOS;
    if (targetOS != OS.macOS && targetOS != OS.iOS) return;

    // CBuilder only emits `-framework X` when language is Objective-C,
    // so we pass framework flags directly for a plain-C helper.
    const frameworks = [
      'CoreFoundation',
      'CoreVideo',
      'CoreMedia',
      'VideoToolbox',
    ];
    final builder = CBuilder.library(
      name: 'webdartc_vt_helper',
      assetName: 'codec/h264/videotoolbox/vt_helper.dart',
      sources: ['src/webdartc_vt_helper.c'],
      flags: [for (final f in frameworks) ...['-framework', f]],
    );
    await builder.run(input: input, output: output);
  });
}
