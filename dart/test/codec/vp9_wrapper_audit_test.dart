/// Audits the bundled `libwebdartc_vp9` dylib's exported symbol table.
/// Mirrors vp8_wrapper_audit_test — same justification, same enforcement.
@Tags(['native'])
@TestOn('mac-os || linux')
library;

import 'package:test/test.dart';

import 'dylib_audit_helpers.dart';

const _expectedExports = {
  'webdartc_vp9_encoder_create',
  'webdartc_vp9_encoder_destroy',
  'webdartc_vp9_encoder_encode',
  'webdartc_vp9_encoder_drain_one',
  'webdartc_vp9_output_data',
  'webdartc_vp9_output_size',
  'webdartc_vp9_output_pts_us',
  'webdartc_vp9_output_is_keyframe',
  'webdartc_vp9_output_free',
  'webdartc_vp9_decoder_create',
  'webdartc_vp9_decoder_destroy',
  'webdartc_vp9_decoder_decode',
  'webdartc_vp9_decoder_drain_one',
  'webdartc_vp9_frame_data',
  'webdartc_vp9_frame_width',
  'webdartc_vp9_frame_height',
  'webdartc_vp9_frame_pts_us',
  'webdartc_vp9_frame_free',
  'webdartc_vp9_get_version_string',
};

void main() {
  test('webdartc_vp9 dylib exports exactly the wrapper API and zero vpx_*',
      () {
    auditWrapperExports(
      dylibBasename: 'libwebdartc_vp9',
      expectedExports: _expectedExports,
      foreignPrefix: 'vpx_',
      bindingsPath: 'lib/src/codec/vp9/_libvpx9.dart',
    );
  });
}
