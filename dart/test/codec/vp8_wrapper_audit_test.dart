/// Audits the bundled `libwebdartc_vp8` dylib's exported symbol table.
///
/// Auto-update of the libvpx submodule must not silently change which
/// symbols leave the dylib: every leaked `vpx_*` symbol risks colliding
/// with another libvpx loaded into the same process (Chromium-based
/// Flutter renderers, third-party plugins, etc.), and any new
/// `webdartc_vp8_*` export needs a matching Dart binding.
@Tags(['native'])
@TestOn('mac-os || linux')
library;

import 'package:test/test.dart';

import 'dylib_audit_helpers.dart';

const _expectedExports = {
  'webdartc_vp8_encoder_create',
  'webdartc_vp8_encoder_destroy',
  'webdartc_vp8_encoder_encode',
  'webdartc_vp8_encoder_drain_one',
  'webdartc_vp8_output_data',
  'webdartc_vp8_output_size',
  'webdartc_vp8_output_pts_us',
  'webdartc_vp8_output_is_keyframe',
  'webdartc_vp8_output_free',
  'webdartc_vp8_decoder_create',
  'webdartc_vp8_decoder_destroy',
  'webdartc_vp8_decoder_decode',
  'webdartc_vp8_decoder_drain_one',
  'webdartc_vp8_frame_data',
  'webdartc_vp8_frame_width',
  'webdartc_vp8_frame_height',
  'webdartc_vp8_frame_pts_us',
  'webdartc_vp8_frame_free',
  'webdartc_vp8_get_version_string',
};

void main() {
  test('webdartc_vp8 dylib exports exactly the wrapper API and zero vpx_*',
      () {
    auditWrapperExports(
      dylibBasename: 'libwebdartc_vp8',
      expectedExports: _expectedExports,
      foreignPrefix: 'vpx_',
      bindingsPath: 'lib/codec/vp8/_libvpx.dart',
    );
  });
}
