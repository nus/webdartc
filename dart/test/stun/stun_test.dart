import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';
import 'package:webdartc/src/stun/builder.dart';
import 'package:webdartc/src/stun/parser.dart';
import 'package:webdartc/src/stun/message.dart';
import 'package:webdartc/src/crypto/csprng.dart';

void main() {
  group('STUN Parser', () {
    test('isStun rejects too-short packet', () {
      expect(StunParser.isStun(Uint8List(10)), isFalse);
    });

    test('isStun rejects packet with wrong magic cookie', () {
      final pkt = Uint8List(20);
      pkt[0] = 0x00;
      pkt[1] = 0x01;
      // Wrong magic cookie
      pkt[4] = 0xFF;
      expect(StunParser.isStun(pkt), isFalse);
    });

    test('isStun accepts valid STUN header', () {
      final pkt = Uint8List(20);
      // Magic cookie at bytes 4-7
      pkt[4] = 0x21; pkt[5] = 0x12; pkt[6] = 0xA4; pkt[7] = 0x42;
      expect(StunParser.isStun(pkt), isTrue);
    });

    test('parse binding request round-trip', () {
      final txId = Csprng.randomBytes(12);
      final msg = StunMessage(
        type: StunMessageType.bindingRequest,
        transactionId: txId,
        attributes: [
          UsernameAttr('user:pass'),
        ],
      );
      final raw = StunMessageBuilder.build(msg);
      expect(StunParser.isStun(raw), isTrue);

      final parsed = StunParser.parse(raw);
      expect(parsed.isOk, isTrue);
      final m = parsed.value;
      expect(m.type, equals(StunMessageType.bindingRequest));
      expect(m.transactionId, equals(txId));
      final user = m.attribute<UsernameAttr>();
      expect(user?.username, equals('user:pass'));
    });

    test('buildWithIntegrity adds MESSAGE-INTEGRITY and FINGERPRINT', () {
      final txId = Csprng.randomBytes(12);
      final msg = StunMessage(
        type: StunMessageType.bindingSuccessResponse,
        transactionId: txId,
        attributes: [
          XorMappedAddress(
            address: IpAddress.parse('192.168.1.1'),
            port: 54321,
          ),
        ],
      );
      final key = Uint8List.fromList('password'.codeUnits);
      final raw = StunMessageBuilder.buildWithIntegrity(msg, key);
      final parsed = StunParser.parse(raw);
      expect(parsed.isOk, isTrue);

      final integrity = parsed.value.attribute<MessageIntegrityAttr>();
      expect(integrity, isNotNull);
      final fp = parsed.value.attribute<FingerprintAttr>();
      expect(fp, isNotNull);
    });

    test('verifyMessageIntegrity accepts a correctly-signed message', () {
      final msg = StunMessage(
        type: StunMessageType.bindingRequest,
        transactionId: Csprng.randomBytes(12),
        attributes: [
          UsernameAttr('local:remote'),
          PriorityAttr(0x7E0000FF),
          IceControllingAttr(0x1122334455667788),
        ],
      );
      final key = Uint8List.fromList('s3cr3t'.codeUnits);
      // With FINGERPRINT (the connectivity-check wire shape) and without.
      for (final fingerprint in [true, false]) {
        final raw =
            StunMessageBuilder.buildWithIntegrity(msg, key, fingerprint: fingerprint);
        expect(StunMessageBuilder.verifyMessageIntegrity(raw, key), isTrue,
            reason: 'fingerprint=$fingerprint');
      }
    });

    test('verifyMessageIntegrity rejects a wrong key', () {
      final msg = StunMessage(
        type: StunMessageType.bindingRequest,
        transactionId: Csprng.randomBytes(12),
        attributes: [UsernameAttr('local:remote')],
      );
      final raw = StunMessageBuilder.buildWithIntegrity(
          msg, Uint8List.fromList('right'.codeUnits));
      expect(
          StunMessageBuilder.verifyMessageIntegrity(
              raw, Uint8List.fromList('wrong'.codeUnits)),
          isFalse);
    });

    test('verifyMessageIntegrity rejects a tampered attribute', () {
      final msg = StunMessage(
        type: StunMessageType.bindingRequest,
        transactionId: Csprng.randomBytes(12),
        attributes: [PriorityAttr(0x7E0000FF)],
      );
      final key = Uint8List.fromList('s3cr3t'.codeUnits);
      final raw = StunMessageBuilder.buildWithIntegrity(msg, key);
      // Flip a byte inside the PRIORITY value (offset 20 = first attr
      // header, 24 = first value byte).
      raw[24] ^= 0xFF;
      expect(StunMessageBuilder.verifyMessageIntegrity(raw, key), isFalse);
    });

    test('verifyMessageIntegrity rejects a message with no integrity attr', () {
      final raw = StunMessageBuilder.build(StunMessage(
        type: StunMessageType.bindingRequest,
        transactionId: Csprng.randomBytes(12),
        attributes: [UsernameAttr('local:remote')],
      ));
      expect(
          StunMessageBuilder.verifyMessageIntegrity(
              raw, Uint8List.fromList('any'.codeUnits)),
          isFalse);
    });

    test('XorMappedAddress IPv4 encode/decode', () {
      final txId = Csprng.randomBytes(12);
      final msg = StunMessage(
        type: StunMessageType.bindingSuccessResponse,
        transactionId: txId,
        attributes: [
          XorMappedAddress(address: IpAddress.parse('10.0.0.1'), port: 4567),
        ],
      );
      final raw = StunMessageBuilder.build(msg);
      final parsed = StunParser.parse(raw);
      expect(parsed.isOk, isTrue);
      final xma = parsed.value.attribute<XorMappedAddress>();
      expect(xma?.address, equals(IpAddress.parse('10.0.0.1')));
      expect(xma?.address.isV4, isTrue);
      expect(xma?.port, equals(4567));
    });

    test('XorMappedAddress IPv6 encode/decode', () {
      final txId = Csprng.randomBytes(12);
      final msg = StunMessage(
        type: StunMessageType.bindingSuccessResponse,
        transactionId: txId,
        attributes: [
          XorMappedAddress(
            address: IpAddress.parse('2001:db8::1'),
            port: 9999,
          ),
        ],
      );
      final raw = StunMessageBuilder.build(msg);
      final parsed = StunParser.parse(raw);
      expect(parsed.isOk, isTrue);
      final xma = parsed.value.attribute<XorMappedAddress>();
      expect(xma?.address, equals(IpAddress.parse('2001:db8::1')));
      expect(xma?.address.isV6, isTrue);
      expect(xma?.port, equals(9999));
    });

    test('MappedAddress IPv4 encode/decode', () {
      final txId = Csprng.randomBytes(12);
      final msg = StunMessage(
        type: StunMessageType.bindingSuccessResponse,
        transactionId: txId,
        attributes: [
          MappedAddress(address: IpAddress.parse('10.0.0.2'), port: 1234),
        ],
      );
      final raw = StunMessageBuilder.build(msg);
      final parsed = StunParser.parse(raw);
      expect(parsed.isOk, isTrue);
      final ma = parsed.value.attribute<MappedAddress>();
      expect(ma?.address, equals(IpAddress.parse('10.0.0.2')));
      expect(ma?.port, equals(1234));
      expect(ma?.family, equals(0x01));
    });

    test('MappedAddress IPv6 encode/decode', () {
      final txId = Csprng.randomBytes(12);
      final msg = StunMessage(
        type: StunMessageType.bindingSuccessResponse,
        transactionId: txId,
        attributes: [
          MappedAddress(address: IpAddress.parse('::1'), port: 4242),
        ],
      );
      final raw = StunMessageBuilder.build(msg);
      final parsed = StunParser.parse(raw);
      expect(parsed.isOk, isTrue);
      final ma = parsed.value.attribute<MappedAddress>();
      expect(ma?.address, equals(IpAddress.parse('::1')));
      expect(ma?.port, equals(4242));
      expect(ma?.family, equals(0x02));
    });
  });
}
