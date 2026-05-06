// Build hook: compiles the VideoToolbox callback shim on macOS/iOS.
//
// The shim is a small C library (`src/wvt_callback.c`) that receives VT
// compression/decompression callbacks on VT's worker threads, CFRetains
// the resulting buffer, and pushes a node onto a thread-safe native queue.
// The Dart side drains the queue from the isolate thread and does the
// actual byte extraction via the ffigen-generated bindings.
//
// On non-Apple platforms the hook is a no-op — VideoToolbox is macOS/iOS
// only.

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:native_toolchain_c/native_toolchain_c.dart';

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;
    final targetOS = input.config.code.targetOS;
    if (targetOS != OS.macOS && targetOS != OS.iOS) return;

    // CBuilder only emits `-framework X` when language is Objective-C, so we
    // pass framework flags directly for a plain-C shim.
    const frameworks = [
      'CoreFoundation',
      'CoreVideo',
      'CoreMedia',
      'VideoToolbox',
    ];
    final builder = CBuilder.library(
      name: 'wvt_callback',
      assetName: 'codec/h264/videotoolbox/wvt_callback.dart',
      sources: ['src/wvt_callback.c'],
      flags: [for (final f in frameworks) ...['-framework', f]],
    );
    await builder.run(input: input, output: output);
  });
}
