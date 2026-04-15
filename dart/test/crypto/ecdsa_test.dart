import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('EcdsaCertificate', () {
    test('selfSigned creates certificate', () {
      final cert = EcdsaCertificate.selfSigned();
      expect(cert.sha256Fingerprint, isNotEmpty);
      expect(cert.sha256Fingerprint.length, greaterThan(10));
    });

    test('sign produces non-empty signature', () {
      final cert = EcdsaCertificate.selfSigned();
      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      final sig = cert.sign(data);
      expect(sig.length, greaterThan(0));
    });
  });
}
