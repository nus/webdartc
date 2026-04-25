import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/dtls/v13/handshake.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);

  /// Hand-build a minimal but well-formed DTLS 1.3 ClientHello body.
  Uint8List buildSampleClientHelloBody({
    required Uint8List random,
    required Uint8List cookie,
    required List<int> cipherSuites,
    required List<TlsExtension> extensions,
    Uint8List? sessionId,
  }) {
    final sid = sessionId ?? Uint8List(0);
    final extBlock = buildTlsExtensionsBlock(extensions);
    final csTotal = cipherSuites.length * 2;
    final body = Uint8List(
      2 + 32 + 1 + sid.length + 1 + cookie.length + 2 + csTotal +
          1 + 1 + extBlock.length,
    );
    var off = 0;
    body[off++] = 0xFE; body[off++] = 0xFD; // legacy_version DTLS 1.2
    body.setRange(off, off + 32, random); off += 32;
    body[off++] = sid.length;
    body.setRange(off, off + sid.length, sid); off += sid.length;
    body[off++] = cookie.length;
    body.setRange(off, off + cookie.length, cookie); off += cookie.length;
    body[off++] = (csTotal >> 8) & 0xFF;
    body[off++] = csTotal & 0xFF;
    for (final s in cipherSuites) {
      body[off++] = (s >> 8) & 0xFF;
      body[off++] = s & 0xFF;
    }
    body[off++] = 1; // compression_methods length
    body[off++] = 0; // null compression
    body.setRange(off, off + extBlock.length, extBlock);
    return body;
  }

  group('TLS extensions block codec', () {
    test('build → parse round trip preserves order and data', () {
      final exts = [
        TlsExtension(0x0017, Uint8List(0)),                          // EMS
        TlsExtension(0x002B, bytes([0x02, 0xFE, 0xFC])),             // SV
        TlsExtension(0x0033, bytes([0x00, 0x04, 0x00, 0x1D, 0x00, 0x00])), // KS
      ];
      final encoded = buildTlsExtensionsBlock(exts);
      final decoded = parseTlsExtensionsBlock(encoded, 0);
      expect(decoded, isNotNull);
      expect(decoded!.length, equals(3));
      expect(decoded[0].type, equals(0x0017));
      expect(decoded[0].data, equals(Uint8List(0)));
      expect(decoded[1].type, equals(0x002B));
      expect(decoded[1].data, equals(bytes([0x02, 0xFE, 0xFC])));
      expect(decoded[2].type, equals(0x0033));
    });

    test('parse rejects truncated block', () {
      final block = bytes([0x00, 0x04, 0x00, 0x17]); // says 4, has only 2
      expect(parseTlsExtensionsBlock(block, 0), isNull);
    });
  });

  group('parseClientHello', () {
    test('parses a hand-crafted DTLS 1.3 ClientHello', () {
      final random = bytes(List<int>.generate(32, (i) => i));
      final cookie = Uint8List(0);
      final exts = [
        TlsExtension(
          TlsV13ExtensionType.supportedVersions,
          // List length 2, then 0xFEFC (DTLS 1.3) — RFC 8446 §4.2.1.
          bytes([0x02, 0xFE, 0xFC]),
        ),
        TlsExtension(
          TlsV13ExtensionType.supportedGroups,
          // length 2, secp256r1
          bytes([0x00, 0x02, 0x00, 0x17]),
        ),
        TlsExtension(
          TlsV13ExtensionType.signatureAlgorithms,
          // length 2, ecdsa_secp256r1_sha256
          bytes([0x00, 0x02, 0x04, 0x03]),
        ),
        TlsExtension(
          TlsV13ExtensionType.keyShare,
          // total 8: one entry — group secp256r1, key_exchange 4 zero bytes
          bytes([
            0x00, 0x08, 0x00, 0x17, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD,
          ]),
        ),
      ];
      final body = buildSampleClientHelloBody(
        random: random,
        cookie: cookie,
        cipherSuites: const [0x1301, 0x1302],
        extensions: exts,
      );
      final ch = parseClientHello(body);
      expect(ch, isNotNull);
      expect(ch!.legacyVersion, equals(0xFEFD));
      expect(ch.random, equals(random));
      expect(ch.cookie, isEmpty);
      expect(ch.cipherSuites, equals([0x1301, 0x1302]));
      expect(ch.compressionMethods, equals([0]));
      expect(ch.extensions.length, equals(4));

      final sv = ch.extensionByType(TlsV13ExtensionType.supportedVersions);
      expect(sv, isNotNull);
      expect(parseClientHelloSupportedVersionsExtData(sv!.data),
          equals([dtls13Version]));

      final ks = ch.extensionByType(TlsV13ExtensionType.keyShare);
      expect(ks, isNotNull);
      final entries = parseClientHelloKeyShareExtData(ks!.data);
      expect(entries, isNotNull);
      expect(entries!.length, equals(1));
      expect(entries[0].group, equals(TlsV13NamedGroup.secp256r1));
      expect(entries[0].keyExchange, equals(bytes([0xAA, 0xBB, 0xCC, 0xDD])));
    });

    test('parses a ClientHello carrying a non-empty cookie', () {
      final cookie = bytes(List<int>.generate(16, (i) => 0xC0 + i));
      final body = buildSampleClientHelloBody(
        random: Uint8List(32),
        cookie: cookie,
        cipherSuites: const [0x1301],
        extensions: [],
      );
      final ch = parseClientHello(body);
      expect(ch, isNotNull);
      expect(ch!.cookie, equals(cookie));
    });

    test('rejects an empty cipher_suites list', () {
      final body = buildSampleClientHelloBody(
        random: Uint8List(32),
        cookie: Uint8List(0),
        cipherSuites: const [], // RFC requires at least one suite.
        extensions: [],
      );
      expect(parseClientHello(body), isNull);
    });

    test('rejects truncated body before cookie', () {
      final body = bytes([
        0xFE, 0xFD,             // legacy_version
        ...List<int>.filled(32, 0), // random
        0,                      // session_id length 0
        // missing cookie length byte → must fail
      ]);
      expect(parseClientHello(body), isNull);
    });
  });

  group('ServerHello build/parse', () {
    test('round trip preserves all fields', () {
      final random = bytes(List<int>.generate(32, (i) => 0x80 ^ i));
      final exts = [
        TlsExtension(
          TlsV13ExtensionType.supportedVersions,
          buildServerHelloSupportedVersionsExtData(dtls13Version),
        ),
        TlsExtension(
          TlsV13ExtensionType.keyShare,
          buildServerHelloKeyShareExtData(
            namedGroup: TlsV13NamedGroup.secp256r1,
            keyExchange: bytes(List<int>.generate(65, (i) => i)),
          ),
        ),
      ];
      final body = buildServerHelloBody(
        random: random,
        legacySessionIdEcho: bytes([0x11, 0x22, 0x33]),
        cipherSuite: 0x1301,
        extensions: exts,
      );
      final parsed = parseServerHelloBody(body);
      expect(parsed, isNotNull);
      expect(parsed!.legacyVersion, equals(0xFEFD));
      expect(parsed.random, equals(random));
      expect(parsed.legacySessionIdEcho, equals(bytes([0x11, 0x22, 0x33])));
      expect(parsed.cipherSuite, equals(0x1301));
      expect(parsed.legacyCompressionMethod, equals(0));
      expect(parsed.extensions.length, equals(2));
      expect(parsed.extensions[0].type,
          equals(TlsV13ExtensionType.supportedVersions));
      expect(parsed.extensions[0].data, equals(bytes([0xFE, 0xFC])));
    });

    test('rejects 31-byte random', () {
      expect(
        () => buildServerHelloBody(
          random: Uint8List(31),
          legacySessionIdEcho: Uint8List(0),
          cipherSuite: 0x1301,
          extensions: const [],
        ),
        throwsArgumentError,
      );
    });
  });

  group('wrapHandshake', () {
    test('produces a 12-byte DTLS handshake header followed by the body', () {
      final body = bytes(List<int>.generate(20, (i) => i + 1));
      final wrapped = wrapHandshake(
        msgType: TlsV13HandshakeType.serverHello,
        msgSeq: 0x0102,
        body: body,
      );
      expect(wrapped.length, equals(12 + body.length));
      expect(wrapped[0], equals(2)); // server_hello
      // 24-bit length = body.length
      expect((wrapped[1] << 16) | (wrapped[2] << 8) | wrapped[3],
          equals(body.length));
      // msg_seq
      expect((wrapped[4] << 8) | wrapped[5], equals(0x0102));
      // fragment_offset = 0
      expect(wrapped.sublist(6, 9), equals(bytes([0, 0, 0])));
      // fragment_length = body.length
      expect((wrapped[9] << 16) | (wrapped[10] << 8) | wrapped[11],
          equals(body.length));
      expect(wrapped.sublist(12), equals(body));
    });
  });

  group('Certificate body', () {
    test('encodes certificate_request_context + per-cert extensions', () {
      final cert = bytes(List<int>.generate(40, (i) => 0xA0 + i));
      final body = buildCertificateBody(
        certificateRequestContext: Uint8List(0),
        certDerChain: [cert],
      );
      // request_context length = 0
      expect(body[0], equals(0));
      // certificate_list 24-bit length = 3 (cert len) + cert.length + 2 (exts)
      final listLen = (body[1] << 16) | (body[2] << 8) | body[3];
      expect(listLen, equals(3 + cert.length + 2));
      // First cert entry: 3-byte length, then cert bytes, then 2 zero bytes.
      final entryOff = 4;
      final entryLen = (body[entryOff] << 16) |
          (body[entryOff + 1] << 8) |
          body[entryOff + 2];
      expect(entryLen, equals(cert.length));
      expect(body.sublist(entryOff + 3, entryOff + 3 + cert.length),
          equals(cert));
      expect(body.sublist(entryOff + 3 + cert.length,
                          entryOff + 3 + cert.length + 2),
          equals(bytes([0, 0])));
    });

    test('rejects request_context > 255 bytes', () {
      expect(
        () => buildCertificateBody(
          certificateRequestContext: Uint8List(256),
          certDerChain: [bytes([1])],
        ),
        throwsArgumentError,
      );
    });
  });

  group('CertificateVerify', () {
    test('signed content begins with 64×0x20 + label + 0x00 + transcript', () {
      final th = bytes(List<int>.generate(32, (i) => i));
      final content = certificateVerifySignedContent(
        transcriptHash: th,
        isServer: true,
      );
      // First 64 bytes are space (0x20).
      for (var i = 0; i < 64; i++) {
        expect(content[i], equals(0x20));
      }
      const label = 'TLS 1.3, server CertificateVerify';
      expect(
        String.fromCharCodes(content.sublist(64, 64 + label.length)),
        equals(label),
      );
      expect(content[64 + label.length], equals(0));
      expect(
        content.sublist(64 + label.length + 1),
        equals(th),
      );
    });

    test('client variant uses the client label', () {
      final content = certificateVerifySignedContent(
        transcriptHash: Uint8List(32),
        isServer: false,
      );
      const label = 'TLS 1.3, client CertificateVerify';
      expect(
        String.fromCharCodes(content.sublist(64, 64 + label.length)),
        equals(label),
      );
    });

    test('body packs scheme + signature with a 16-bit length', () {
      final sig = bytes(List<int>.generate(72, (i) => i));
      final body = buildCertificateVerifyBody(
        signatureScheme: TlsV13SignatureScheme.ecdsaSecp256r1Sha256,
        signature: sig,
      );
      expect((body[0] << 8) | body[1], equals(0x0403));
      expect((body[2] << 8) | body[3], equals(sig.length));
      expect(body.sublist(4), equals(sig));
    });
  });

  group('Finished + EncryptedExtensions', () {
    test('Finished body is the verify_data verbatim', () {
      final vd = bytes(List<int>.generate(32, (i) => 0xF0 ^ i));
      expect(buildFinishedBody(vd), equals(vd));
    });

    test('EncryptedExtensions round trip with a non-empty list', () {
      final exts = [
        TlsExtension(TlsV13ExtensionType.useSrtp,
            bytes([0x00, 0x02, 0x00, 0x01, 0x00])),
        TlsExtension(TlsV13ExtensionType.alpn,
            bytes([0x00, 0x09, 0x08, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63, 0x73])),
      ];
      final encoded = buildEncryptedExtensionsBody(exts);
      final decoded = parseEncryptedExtensionsBody(encoded);
      expect(decoded, isNotNull);
      expect(decoded!.length, equals(2));
      expect(decoded[0].type, equals(TlsV13ExtensionType.useSrtp));
      expect(decoded[1].type, equals(TlsV13ExtensionType.alpn));
    });
  });

  group('Extension data helpers', () {
    test('signature_algorithms parses 2-byte schemes with length prefix', () {
      // length 4, schemes 0x0403, 0x0804
      final data = bytes([0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
      final out = parseSignatureAlgorithmsExtData(data);
      expect(out, equals([0x0403, 0x0804]));
    });

    test('ServerHello supported_versions ext data is exactly 2 bytes', () {
      final data = buildServerHelloSupportedVersionsExtData(dtls13Version);
      expect(data, equals(bytes([0xFE, 0xFC])));
    });

    test('ClientHello supported_versions parses uint8 + uint16 list', () {
      final out =
          parseClientHelloSupportedVersionsExtData(bytes([0x04, 0xFE, 0xFC, 0xFE, 0xFD]));
      expect(out, equals([dtls13Version, dtls12Version]));
    });

    test('key_share ServerHello build round trips through ClientHello parse',
        () {
      // The ServerHello form is a single entry; the ClientHello form is a
      // list. Wrap the ServerHello bytes in an outer length to feed the
      // ClientHello parser.
      final serverEntry = buildServerHelloKeyShareExtData(
        namedGroup: TlsV13NamedGroup.x25519,
        keyExchange: bytes(List<int>.generate(32, (i) => i)),
      );
      final asListData = Uint8List(2 + serverEntry.length);
      asListData[0] = (serverEntry.length >> 8) & 0xFF;
      asListData[1] = serverEntry.length & 0xFF;
      asListData.setRange(2, asListData.length, serverEntry);
      final entries = parseClientHelloKeyShareExtData(asListData);
      expect(entries, isNotNull);
      expect(entries!.length, equals(1));
      expect(entries[0].group, equals(TlsV13NamedGroup.x25519));
      expect(entries[0].keyExchange.length, equals(32));
    });
  });
}
