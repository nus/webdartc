/// Shared helpers for the codec wrapper-audit tests
/// (`vp{8,9}_wrapper_audit_test.dart`). Locating the dylib and parsing
/// `nm` output isn't codec-specific, only the dylib basename and
/// expected symbol set are.
library;

import 'dart:io';

import 'package:test/test.dart';

/// Locate the wrapper dylib for the given basename (e.g.
/// `libwebdartc_vp8` or `libwebdartc_vp9`). Returns null when the
/// build hook hasn't produced it yet — tests should `markTestSkipped`
/// in that case.
String? findDylib(String basename) {
  final ext = Platform.isMacOS ? 'dylib' : 'so';
  // `dart test` lands the asset under .dart_tool/lib/ relative to the
  // package root — that's the cwd when these tests run.
  final canonical = File('.dart_tool/lib/$basename.$ext');
  if (canonical.existsSync()) return canonical.path;
  // Flutter / hooks_runner caches keep their copy under
  // .dart_tool/hooks_runner/ — fall back to a scoped walk only there.
  final cache = Directory('.dart_tool/hooks_runner');
  if (!cache.existsSync()) return null;
  for (final entity in cache.listSync(recursive: true, followLinks: false)) {
    if (entity is File && entity.path.endsWith('$basename.$ext')) {
      return entity.path;
    }
  }
  return null;
}

/// List defined dynamic symbols, stripped of the macOS leading `_`
/// prefix so callers compare against bare C names on both platforms.
List<String> readDynamicSymbols(String dylibPath) {
  // BSD nm on macOS, GNU nm on Linux — different flag spellings.
  final args = Platform.isMacOS
      ? ['-gj', dylibPath]
      : ['-D', '--defined-only', '--format=just-symbols', dylibPath];
  final result = Process.runSync('nm', args);
  if (result.exitCode != 0) {
    throw StateError('nm $args failed:\n${result.stderr}');
  }
  return (result.stdout as String)
      .split('\n')
      .map((s) => s.trim())
      .where((s) => s.isNotEmpty)
      .map((s) => Platform.isMacOS && s.startsWith('_') ? s.substring(1) : s)
      .toList();
}

/// Asserts the dylib exports exactly [expectedExports] (all
/// `webdartc_*`) and zero symbols of [foreignPrefix] (the underlying
/// upstream library — e.g. `vpx_` for libvpx, `opus_` for libopus).
/// Skips the test if the dylib hasn't been built yet.
void auditWrapperExports({
  required String dylibBasename,
  required Set<String> expectedExports,
  required String foreignPrefix,
  required String bindingsPath,
}) {
  final dylib = findDylib(dylibBasename);
  if (dylib == null) {
    markTestSkipped('$dylibBasename not built yet');
    return;
  }

  final exported = readDynamicSymbols(dylib);
  final webdartc = exported.where((s) => s.startsWith('webdartc_')).toSet();
  final foreign = exported.where((s) => s.startsWith(foreignPrefix)).toList()
    ..sort();

  expect(foreign, isEmpty,
      reason: 'upstream symbols leaked through hidden visibility — '
          'auto-update may have changed how the library marks public APIs');
  expect(webdartc, equals(expectedExports),
      reason:
          'wrapper exports drifted; update expectedExports + Dart bindings '
          '($bindingsPath) to match the C header');
}
