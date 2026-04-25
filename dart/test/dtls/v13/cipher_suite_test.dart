import 'package:test/test.dart';
import 'package:webdartc/dtls/v13/cipher_suite.dart';

void main() {
  group('TlsV13CipherSuite', () {
    test('TLS_AES_128_GCM_SHA256 has the RFC 8446 fixed parameters', () {
      const s = TlsV13CipherSuite.aes128GcmSha256;
      expect(s.id, equals(0x1301));
      expect(s.name, equals('TLS_AES_128_GCM_SHA256'));
      expect(s.keyLength, equals(16));   // AES-128
      expect(s.ivLength, equals(12));    // GCM nonce
      expect(s.hashLength, equals(32));  // SHA-256
      expect(s.tagLength, equals(16));   // GCM tag
    });

    test('byId returns the suite for known IDs and null otherwise', () {
      expect(TlsV13CipherSuite.byId(0x1301),
          same(TlsV13CipherSuite.aes128GcmSha256));
      expect(TlsV13CipherSuite.byId(0x1303),
          same(TlsV13CipherSuite.chacha20Poly1305Sha256));
      expect(TlsV13CipherSuite.byId(0x0000), isNull);
      expect(TlsV13CipherSuite.byId(0x1302), isNull); // AES_256_GCM not yet supported
    });

    test('selectFromOffer picks the first supported ID in client order', () {
      final picked = TlsV13CipherSuite.selectFromOffer(const [
        0x1302, // unsupported AES_256_GCM_SHA384
        0x1301, // supported AES_128_GCM_SHA256
        0x1303, // supported CHACHA20_POLY1305_SHA256 (later in offer)
        0x1304, // unknown
      ]);
      expect(picked, same(TlsV13CipherSuite.aes128GcmSha256));
    });

    test('selectFromOffer picks ChaCha20-Poly1305 when offered first', () {
      final picked = TlsV13CipherSuite.selectFromOffer(const [
        0x1303, // supported CHACHA20_POLY1305_SHA256
        0x1301, // also supported, but later
      ]);
      expect(picked, same(TlsV13CipherSuite.chacha20Poly1305Sha256));
    });

    test('selectFromOffer returns null when there is no overlap', () {
      expect(
        TlsV13CipherSuite.selectFromOffer(const [0x1302, 0x1304]),
        isNull,
      );
    });

    test('TLS_CHACHA20_POLY1305_SHA256 has the RFC 8446 fixed parameters', () {
      const s = TlsV13CipherSuite.chacha20Poly1305Sha256;
      expect(s.id, equals(0x1303));
      expect(s.name, equals('TLS_CHACHA20_POLY1305_SHA256'));
      expect(s.keyLength, equals(32));  // ChaCha20 key
      expect(s.ivLength, equals(12));   // Poly1305 AEAD nonce
      expect(s.hashLength, equals(32)); // SHA-256
      expect(s.tagLength, equals(16));  // Poly1305 tag
    });

    test('supported list contains exactly the suites byId can find', () {
      for (final s in TlsV13CipherSuite.supported) {
        expect(TlsV13CipherSuite.byId(s.id), same(s));
      }
    });
  });
}
