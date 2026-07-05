/// Unit tests for [detectDtlsVersion] — the single server-side sniff that
/// routes a first ClientHello to the DTLS 1.2 or DTLS 1.3 path (used by
/// `DtlsStateMachine`'s server role; the delegation itself is covered by
/// v13_delegation_test.dart).
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/dtls/record.dart';
import 'package:webdartc/src/dtls/version_detect.dart';
import 'package:webdartc/src/dtls/v13/handshake.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);

  /// Build the body of a minimal ClientHello (no DTLS handshake wrapper).
  Uint8List buildClientHelloBody({
    required Uint8List random,
    required List<int> cipherSuites,
    required List<TlsExtension> extensions,
    Uint8List? cookie,
  }) {
    final ck = cookie ?? Uint8List(0);
    final extBlock = buildTlsExtensionsBlock(extensions);
    final csTotal = cipherSuites.length * 2;
    final body = Uint8List(
      2 + 32 + 1 + 1 + ck.length + 2 + csTotal + 1 + 1 + extBlock.length,
    );
    var off = 0;
    body[off++] = 0xFE; body[off++] = 0xFD;
    body.setRange(off, off + 32, random); off += 32;
    body[off++] = 0; // session_id length
    body[off++] = ck.length;
    body.setRange(off, off + ck.length, ck); off += ck.length;
    body[off++] = (csTotal >> 8) & 0xFF;
    body[off++] = csTotal & 0xFF;
    for (final s in cipherSuites) {
      body[off++] = (s >> 8) & 0xFF;
      body[off++] = s & 0xFF;
    }
    body[off++] = 1; body[off++] = 0;
    body.setRange(off, off + extBlock.length, extBlock);
    return body;
  }

  Uint8List wrapAsPlaintextRecord(Uint8List handshakeFragment) {
    return DtlsRecord(
      contentType: DtlsContentType.handshake,
      version: 0xFEFD,
      epoch: 0,
      sequenceNumber: 0,
      fragment: handshakeFragment,
    ).encode();
  }

  Uint8List clientHelloPacket({required List<TlsExtension> extensions}) {
    final body = buildClientHelloBody(
      random: Uint8List(32),
      cipherSuites: const [0x1301, 0xC02B],
      extensions: extensions,
    );
    final hs = wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: 0,
      body: body,
    );
    return wrapAsPlaintextRecord(hs);
  }

  group('detectDtlsVersion', () {
    test('v13 when supported_versions includes 0xFEFC', () {
      final packet = clientHelloPacket(extensions: [
        TlsExtension(
          TlsV13ExtensionType.supportedVersions,
          bytes([0x02, 0xFE, 0xFC]),
        ),
      ]);
      expect(detectDtlsVersion(packet), DtlsVersion.v13);
    });

    test('v12 when supported_versions only lists DTLS 1.2', () {
      final packet = clientHelloPacket(extensions: [
        TlsExtension(
          TlsV13ExtensionType.supportedVersions,
          bytes([0x02, 0xFE, 0xFD]),
        ),
      ]);
      expect(detectDtlsVersion(packet), DtlsVersion.v12);
    });

    test('v12 when supported_versions is absent', () {
      final packet = clientHelloPacket(extensions: const []);
      expect(detectDtlsVersion(packet), DtlsVersion.v12);
    });

    test('null when the packet is not a ClientHello', () {
      expect(detectDtlsVersion(bytes(List<int>.filled(32, 0xFF))), isNull);
    });

    test('null for a non-handshake record', () {
      final rec = DtlsRecord(
        contentType: DtlsContentType.applicationData,
        version: 0xFEFD,
        epoch: 0,
        sequenceNumber: 0,
        fragment: bytes([1, 2, 3]),
      ).encode();
      expect(detectDtlsVersion(rec), isNull);
    });

    test('v13 for a fragmented ClientHello (MTU-split heuristic)', () {
      final body = buildClientHelloBody(
        random: Uint8List(32),
        cipherSuites: const [0x1301],
        extensions: const [],
      );
      final whole = wrapHandshake(
        msgType: TlsV13HandshakeType.clientHello,
        msgSeq: 0,
        body: body,
      );
      // Rewrite the handshake header so fragment_length < length, as the
      // first datagram of an MTU-split ClientHello would carry it.
      final half = body.length ~/ 2;
      final fragmented = Uint8List.fromList([
        ...whole.sublist(0, 12),
        ...body.sublist(0, half),
      ]);
      // fragment_length is bytes 9..11 of the handshake header.
      fragmented[9] = (half >> 16) & 0xFF;
      fragmented[10] = (half >> 8) & 0xFF;
      fragmented[11] = half & 0xFF;
      expect(detectDtlsVersion(wrapAsPlaintextRecord(fragmented)),
          DtlsVersion.v13);
    });
  });
}
