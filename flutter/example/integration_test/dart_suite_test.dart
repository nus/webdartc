// Runs the webdartc Dart package's own platform-relevant tests ON-DEVICE.
//
// Instead of duplicating assertions, this aggregator relative-imports the real
// test files from dart/test/** (each a package:test `void main()`) and runs
// them under the integration_test binding. `package:test` and `package:flutter_test`
// share the same `package:test_api` declarer, so calling each file's main()
// from here (inside the active declarer zone) registers its tests normally.
//
// Only platform-relevant, host-clean files are included — files that need a
// browser (e2e), an external server (coturn), the `nm` CLI (wrapper audits),
// or are Apple-only (@TestOn('mac-os') VideoToolbox) are intentionally left out
// and stay host-only under `dart test`.
//
// Run:  cd flutter/example && flutter test integration_test/dart_suite_test.dart -d <device>
//
// The deep relative imports reach another package's test/ dir (not exposed via
// package: URIs), which the analyzer would flag — suppressed file-wide below.
// ignore_for_file: avoid_relative_lib_imports, depend_on_referenced_packages
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../../../dart/test/crypto/aes_cm_test.dart' as aes_cm;
import '../../../dart/test/crypto/aes_gcm_test.dart' as aes_gcm;
import '../../../dart/test/crypto/chacha20_poly1305_test.dart' as chacha;
import '../../../dart/test/crypto/csprng_test.dart' as csprng;
import '../../../dart/test/crypto/ecdsa_test.dart' as ecdsa;
import '../../../dart/test/crypto/ecdsa_verify_test.dart' as ecdsa_verify;
import '../../../dart/test/crypto/hkdf_test.dart' as hkdf;
import '../../../dart/test/crypto/hmac_sha1_test.dart' as hmac_sha1;
import '../../../dart/test/crypto/hmac_sha256_test.dart' as hmac_sha256;
import '../../../dart/test/crypto/sha_test.dart' as sha;
import '../../../dart/test/crypto/tls_prf_test.dart' as tls_prf;
import '../../../dart/test/crypto/x25519_test.dart' as x25519;

import '../../../dart/test/codec/vp8_decoder_test.dart' as vp8_decoder;
import '../../../dart/test/codec/vp8_encoder_test.dart' as vp8_encoder;
import '../../../dart/test/codec/vp8_encoder_multiframe_test.dart'
    as vp8_encoder_multiframe;
import '../../../dart/test/codec/vp8_multistream_test.dart' as vp8_multistream;
import '../../../dart/test/codec/vp8_roundtrip_test.dart' as vp8_roundtrip;
import '../../../dart/test/codec/vp8_version_test.dart' as vp8_version;
import '../../../dart/test/codec/vp8_wire_format_test.dart' as vp8_wire_format;
import '../../../dart/test/codec/vp9_multistream_test.dart' as vp9_multistream;
import '../../../dart/test/codec/h264_mediacodec_color_test.dart'
    as h264_mediacodec_color;
import '../../../dart/test/codec/h264_mediacodec_multistream_test.dart'
    as h264_mediacodec_multistream;
import '../../../dart/test/codec/h264_mediacodec_roundtrip_test.dart'
    as h264_mediacodec_roundtrip;
import '../../../dart/test/codec/vp9_roundtrip_test.dart' as vp9_roundtrip;
import '../../../dart/test/codec/vp9_version_test.dart' as vp9_version;
import '../../../dart/test/codec/opus_test.dart' as opus;
import '../../../dart/test/codec/opus_libopus_update_test.dart'
    as opus_libopus_update;

import '../../../dart/test/peer_connection/data_channel_open_test.dart'
    as data_channel_open;
import '../../../dart/test/peer_connection/data_channel_test.dart'
    as data_channel;
import '../../../dart/test/peer_connection/ice_gathering_state_test.dart'
    as ice_gathering_state;
import '../../../dart/test/peer_connection/ice_restart_test.dart'
    as ice_restart;
import '../../../dart/test/peer_connection/pc_spec_methods_test.dart'
    as pc_spec_methods;
import '../../../dart/test/peer_connection/transceiver_test.dart'
    as transceiver;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // Each file's main() is wrapped in its own group so its setUpAll/tearDown
  // stay scoped to that file.

  // crypto — exercises the platform backend (Android: JCA via package:jni).
  group('crypto/aes_cm', aes_cm.main);
  group('crypto/aes_gcm', aes_gcm.main);
  group('crypto/chacha20_poly1305', chacha.main);
  group('crypto/csprng', csprng.main);
  group('crypto/ecdsa', ecdsa.main);
  group('crypto/ecdsa_verify', ecdsa_verify.main);
  group('crypto/hkdf', hkdf.main);
  group('crypto/hmac_sha1', hmac_sha1.main);
  group('crypto/hmac_sha256', hmac_sha256.main);
  group('crypto/sha', sha.main);
  group('crypto/tls_prf', tls_prf.main);
  group('crypto/x25519', x25519.main);

  // codec — exercises the NDK cross-compiled libvpx / libopus on Android.
  group('codec/vp8_decoder', vp8_decoder.main);
  group('codec/vp8_encoder', vp8_encoder.main);
  group('codec/vp8_encoder_multiframe', vp8_encoder_multiframe.main);
  group('codec/vp8_multistream', vp8_multistream.main);
  group('codec/vp8_roundtrip', vp8_roundtrip.main);
  group('codec/vp8_version', vp8_version.main);
  group('codec/vp8_wire_format', vp8_wire_format.main);
  group('codec/vp9_multistream', vp9_multistream.main);
  // H.264 via Android MediaCodec (Android-only; host `dart test` skips these).
  group('codec/h264_mediacodec_color', h264_mediacodec_color.main);
  group('codec/h264_mediacodec_multistream', h264_mediacodec_multistream.main);
  group('codec/h264_mediacodec_roundtrip', h264_mediacodec_roundtrip.main);
  group('codec/vp9_roundtrip', vp9_roundtrip.main);
  group('codec/vp9_version', vp9_version.main);
  group('codec/opus', opus.main);
  group('codec/opus_libopus_update', opus_libopus_update.main);

  // peer_connection — full ICE → DTLS → SCTP over dart:io UDP (loopback),
  // driving the platform crypto backend end-to-end.
  group('peer_connection/data_channel_open', data_channel_open.main);
  group('peer_connection/data_channel', data_channel.main);
  group('peer_connection/ice_gathering_state', ice_gathering_state.main);
  group('peer_connection/ice_restart', ice_restart.main);
  group('peer_connection/pc_spec_methods', pc_spec_methods.main);
  group('peer_connection/transceiver', transceiver.main);
}
