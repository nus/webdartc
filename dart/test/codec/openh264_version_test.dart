/// Pins the Cisco-prebuilt OpenH264 version that the bundled dylib
/// reports.
///
/// `dart/hook/build.dart` downloads the binary from
/// `ciscobinary.openh264.org` keyed on `_openH264Version`. When that
/// constant is bumped, this test must move in lockstep — that's the
/// guardrail. The test catches:
///   - `_openH264Version` and `_openH264Sha256` updated but the dylib
///     downloaded was a different version (corrupted CDN fetch),
///   - someone swapping in a stray `libopenh264.so` from the system
///     install instead of the cached prebuilt download.
///
/// macOS uses VideoToolbox so OpenH264 isn't shipped — the test gates
/// itself to platforms that bundle the Cisco prebuilt (Linux + Windows).
@Tags(['native'])
@TestOn('linux || windows')
library;

import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart' as pkgffi;
import 'package:test/test.dart';
import 'package:webdartc/src/codec/h264/_openh264.dart' as wels;
import 'package:webdartc/src/codec/h264/openh264/bindings.g.dart' as oh;

void main() {
  test('bundled OpenH264 reports the pinned version (2.5.1)', () {
    final v = pkgffi.calloc<oh.OpenH264Version>();
    try {
      wels.welsGetCodecVersionEx(v);
      final actual =
          '${v.ref.uMajor}.${v.ref.uMinor}.${v.ref.uRevision}';
      expect(actual, equals('2.5.1'),
          reason: 'bundled OpenH264 version drifted — bump '
              '_openH264Version + _openH264Sha256 in dart/hook/build.dart '
              'and this test, then wipe '
              '`.dart_tool/hooks_runner/shared/webdartc/openh264-*/` so '
              'the cached download is refetched');
    } finally {
      pkgffi.calloc.free(v);
    }
    // Sanity: ffi.nullptr would mean we never resolved against the
    // bundled dylib at all (i.e. the @Native machinery is broken).
    expect(v.address, isNot(equals(ffi.nullptr.address)));
  });
}
