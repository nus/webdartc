import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

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
          XorMappedAddress(ip: '192.168.1.1', port: 54321),
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

    test('XorMappedAddress encode/decode', () {
      final txId = Csprng.randomBytes(12);
      final msg = StunMessage(
        type: StunMessageType.bindingSuccessResponse,
        transactionId: txId,
        attributes: [XorMappedAddress(ip: '10.0.0.1', port: 4567)],
      );
      final raw = StunMessageBuilder.build(msg);
      final parsed = StunParser.parse(raw);
      expect(parsed.isOk, isTrue);
      final xma = parsed.value.attribute<XorMappedAddress>();
      expect(xma?.ip, equals('10.0.0.1'));
      expect(xma?.port, equals(4567));
    });
  });
}
