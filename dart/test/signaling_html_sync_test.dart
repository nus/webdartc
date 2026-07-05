/// Guards the two checked-in copies of the Ayame browser peer page
/// against silent divergence: `example/signaling/index.html` (served by
/// the standalone relay) and the Flutter example's bundled asset
/// (served by its embedded relay). Only the header comments may differ.
library;

import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('browser peer HTML copies are in sync', () {
    final dartCopy = File('example/signaling/index.html');
    final flutterCopy = File('../flutter/example/assets/browser_peer.html');
    if (!dartCopy.existsSync() || !flutterCopy.existsSync()) {
      markTestSkipped('not running from the monorepo checkout');
      return;
    }
    // Everything from <html> onward must match byte-for-byte; the
    // doctype line and the "keep in sync" header comment may differ.
    String body(File f) {
      final s = f.readAsStringSync();
      return s.substring(s.indexOf('<html'));
    }

    expect(body(flutterCopy), body(dartCopy),
        reason: 'browser_peer.html has diverged from '
            'example/signaling/index.html — copy the edit to both files');
  });
}
