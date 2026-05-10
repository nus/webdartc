/// Pins the libvpx submodule version that the bundled wrapper reports.
///
/// On submodule auto-update bumps the dependency to a different libvpx
/// release, this test must be edited in lockstep — that's the whole
/// point. The test catches:
///   - stale build cache (still using the old `.dart_tool/.../vpx-build-*/`)
///   - submodule pointing at the wrong SHA (e.g. forgotten `git submodule
///     update`)
///   - the `webdartc_vp8_get_version_string` binding silently breaking
///     (returns garbage / crashes on a future libvpx layout change).
@Tags(['native'])
@TestOn('mac-os || linux')
library;

import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart' as pkgffi;
import 'package:test/test.dart';
import 'package:webdartc/codec/vp8/_libvpx.dart' as vp8;

void main() {
  test('webdartc_vp8 reports the pinned libvpx version', () {
    final ptr = vp8.vp8GetVersionString();
    expect(ptr, isNot(equals(ffi.nullptr)),
        reason: 'webdartc_vp8_get_version_string returned NULL');

    final actual = ptr.cast<pkgffi.Utf8>().toDartString();

    // libvpx's `vpx_codec_version_str()` returns the form "v1.16.0".
    // Anchor on the major.minor.patch we vendor; bumping the submodule
    // requires bumping this string too.
    expect(actual, equals('v1.16.0'),
        reason: 'bundled libvpx version drifted — update either '
            'dart/third_party/libvpx (submodule SHA) or this test '
            'expectation, then wipe '
            '`.dart_tool/hooks_runner/shared/webdartc/build/vpx-*` so the '
            'cmake/configure cache is rebuilt');
  });
}
