/// Pins the libvpx submodule version that the bundled VP9 wrapper
/// reports. Mirrors vp8_version_test (both wrappers link the SAME
/// libvpx, so the two reported strings should always agree — that's
/// also asserted here).
@Tags(['native'])
@TestOn('mac-os || linux')
library;

import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart' as pkgffi;
import 'package:test/test.dart';
import 'package:webdartc/codec/vp8/_libvpx.dart' as vp8;
import 'package:webdartc/codec/vp9/_libvpx9.dart' as vp9;

void main() {
  test('webdartc_vp9 reports the pinned libvpx version', () {
    final ptr = vp9.vp9GetVersionString();
    expect(ptr, isNot(equals(ffi.nullptr)),
        reason: 'webdartc_vp9_get_version_string returned NULL');

    final actual = ptr.cast<pkgffi.Utf8>().toDartString();
    expect(actual, equals('v1.16.0'),
        reason: 'bundled libvpx version drifted — update either '
            'dart/third_party/libvpx (submodule SHA) or this test '
            'expectation, then wipe '
            '`.dart_tool/hooks_runner/shared/webdartc/build/vpx-*` so the '
            'configure cache is rebuilt');
  });

  test('VP8 and VP9 wrapper dylibs agree on the libvpx version', () {
    final v8 = vp8.vp8GetVersionString().cast<pkgffi.Utf8>().toDartString();
    final v9 = vp9.vp9GetVersionString().cast<pkgffi.Utf8>().toDartString();
    expect(v9, equals(v8),
        reason: 'webdartc_vp8 and webdartc_vp9 must link the same libvpx — '
            'a divergence means one dylib is stale');
  });
}
