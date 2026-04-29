import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/core/types.dart';
import 'package:webdartc/crypto/ecdsa.dart';
import 'package:webdartc/dtls/dispatcher.dart';
import 'package:webdartc/dtls/record.dart';
import 'package:webdartc/dtls/state_machine.dart' as v12;
import 'package:webdartc/dtls/v13/handshake.dart';
import 'package:webdartc/dtls/v13/state_machine.dart' as v13;

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

  Uint8List clientHelloPacket({
    required List<TlsExtension> extensions,
    Uint8List? cookie,
  }) {
    final body = buildClientHelloBody(
      random: Uint8List(32),
      cipherSuites: const [0x1301, 0xC02B],
      extensions: extensions,
      cookie: cookie,
    );
    final hs = wrapHandshake(
      msgType: TlsV13HandshakeType.clientHello,
      msgSeq: 0,
      body: body,
    );
    return wrapAsPlaintextRecord(hs);
  }

  group('DtlsServerDispatcher.processInput selection', () {
    test('routes to DTLS 1.3 when supported_versions includes 0xFEFC', () {
      final cert = EcdsaCertificate.selfSigned();
      final disp = DtlsServerDispatcher(localCert: cert);
      final packet = clientHelloPacket(
        extensions: [
          TlsExtension(
            TlsV13ExtensionType.supportedVersions,
            bytes([0x02, 0xFE, 0xFC]),
          ),
        ],
      );
      // The v13 inner SM will fail validation later (no key_share), but
      // selection happens up front based on supported_versions alone.
      final r = disp.processInput(packet,
          remoteIp: '127.0.0.1', remotePort: 5000);
      expect(disp.isV13, isTrue);
      expect(disp.inner, isA<v13.DtlsV13ServerStateMachine>());
      // r itself may be Err because the body was insufficient; selection
      // was the point of this test.
      expect(r, isNotNull);
    });

    test('routes to DTLS 1.2 when supported_versions only lists DTLS 1.2',
        () {
      final cert = EcdsaCertificate.selfSigned();
      final disp = DtlsServerDispatcher(localCert: cert);
      final packet = clientHelloPacket(
        extensions: [
          TlsExtension(
            TlsV13ExtensionType.supportedVersions,
            bytes([0x02, 0xFE, 0xFD]),
          ),
        ],
      );
      disp.processInput(packet, remoteIp: '127.0.0.1', remotePort: 5000);
      expect(disp.isV13, isFalse);
      expect(disp.inner, isA<v12.DtlsStateMachine>());
    });

    test('routes to DTLS 1.2 when supported_versions is absent', () {
      final cert = EcdsaCertificate.selfSigned();
      final disp = DtlsServerDispatcher(localCert: cert);
      final packet = clientHelloPacket(extensions: const []);
      disp.processInput(packet, remoteIp: '127.0.0.1', remotePort: 5000);
      expect(disp.isV13, isFalse);
      expect(disp.inner, isA<v12.DtlsStateMachine>());
    });

    test('returns ParseError when the first packet is not a ClientHello', () {
      final cert = EcdsaCertificate.selfSigned();
      final disp = DtlsServerDispatcher(localCert: cert);
      // Random non-DTLS bytes.
      final r = disp.processInput(
        bytes(List<int>.filled(32, 0xFF)),
        remoteIp: '127.0.0.1',
        remotePort: 5000,
      );
      expect(r.isErr, isTrue);
      expect(disp.inner, isNull);
      expect(disp.isV13, isNull);
    });

    test('forwards subsequent packets to the chosen inner SM', () {
      final cert = EcdsaCertificate.selfSigned();
      final disp = DtlsServerDispatcher(localCert: cert);
      // Pick v13 with a benign first ClientHello.
      final packet = clientHelloPacket(
        extensions: [
          TlsExtension(
            TlsV13ExtensionType.supportedVersions,
            bytes([0x02, 0xFE, 0xFC]),
          ),
        ],
      );
      disp.processInput(packet, remoteIp: '127.0.0.1', remotePort: 5000);
      expect(disp.inner, isNotNull);
      final firstInner = disp.inner;
      // Even if the second packet errors, dispatcher must not re-select.
      disp.processInput(packet, remoteIp: '127.0.0.1', remotePort: 5000);
      expect(disp.inner, same(firstInner));
    });
  });

  group('DtlsServerDispatcher callback wiring', () {
    test('handleTimeout before any packet is a no-op', () {
      final cert = EcdsaCertificate.selfSigned();
      final disp = DtlsServerDispatcher(localCert: cert);
      // No inner yet; this should not crash and should return success.
      final r = disp.handleTimeout(DtlsRetransmitToken(0));
      expect(r.isOk, isTrue);
      expect(disp.inner, isNull);
    });
  });
}
