@Tags(['native'])
@TestOn('mac-os')
library;

import 'package:test/test.dart';
import 'package:webdartc/codec/h264/videotoolbox/vt_helper.dart';

void main() {
  test('VideoToolbox C helper is loadable and reports ABI version', () {
    expect(webdartcVtHelperAbiVersion(), greaterThanOrEqualTo(1));
  });
}
