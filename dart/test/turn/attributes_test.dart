import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';
import 'package:webdartc/src/stun/builder.dart';
import 'package:webdartc/src/stun/parser.dart';
import 'package:webdartc/src/stun/message.dart';
import 'package:webdartc/src/crypto/csprng.dart';

void main() {
  group('TURN attributes round-trip', () {
    Uint8List roundTrip(List<StunAttribute> attrs) {
      final msg = StunMessage(
        type: StunMessageType.allocateRequest,
        transactionId: Csprng.randomBytes(12),
        attributes: attrs,
      );
      return StunMessageBuilder.build(msg);
    }

    test('REALM', () {
      final raw = roundTrip([const RealmAttr('example.org')]);
      final m = StunParser.parse(raw).value;
      expect(m.attribute<RealmAttr>()?.realm, 'example.org');
    });

    test('NONCE', () {
      final nonce = Uint8List.fromList(List<int>.generate(16, (i) => i));
      final raw = roundTrip([NonceAttr(nonce)]);
      final m = StunParser.parse(raw).value;
      expect(m.attribute<NonceAttr>()?.nonce, nonce);
    });

    test('XOR-PEER-ADDRESS (IPv4)', () {
      final raw = roundTrip([
        XorPeerAddress(
          address: IpAddress.parse('192.0.2.42'),
          port: 12345,
        ),
      ]);
      final m = StunParser.parse(raw).value;
      final attr = m.attribute<XorPeerAddress>();
      expect(attr?.address.toCanonical(), '192.0.2.42');
      expect(attr?.port, 12345);
    });

    test('XOR-RELAYED-ADDRESS (IPv4)', () {
      final raw = roundTrip([
        XorRelayedAddress(
          address: IpAddress.parse('203.0.113.7'),
          port: 49152,
        ),
      ]);
      final m = StunParser.parse(raw).value;
      final attr = m.attribute<XorRelayedAddress>();
      expect(attr?.address.toCanonical(), '203.0.113.7');
      expect(attr?.port, 49152);
    });

    test('DATA preserves payload bytes', () {
      final data = Uint8List.fromList(List<int>.generate(123, (i) => i & 0xFF));
      final raw = roundTrip([DataAttr(data)]);
      final m = StunParser.parse(raw).value;
      expect(m.attribute<DataAttr>()?.data, data);
    });

    test('LIFETIME 32-bit seconds', () {
      final raw = roundTrip([const LifetimeAttr(600)]);
      final m = StunParser.parse(raw).value;
      expect(m.attribute<LifetimeAttr>()?.seconds, 600);
    });

    test('REQUESTED-TRANSPORT carries IANA protocol number', () {
      // UDP is 17 per RFC 5766 §14.7.
      final raw = roundTrip([const RequestedTransportAttr(17)]);
      final m = StunParser.parse(raw).value;
      expect(m.attribute<RequestedTransportAttr>()?.protocol, 17);
    });

    test('CHANNEL-NUMBER 16-bit channel + 16-bit reserved', () {
      final raw = roundTrip([const ChannelNumberAttr(0x4001)]);
      final m = StunParser.parse(raw).value;
      expect(m.attribute<ChannelNumberAttr>()?.channel, 0x4001);
    });

    test('DONT-FRAGMENT has empty value', () {
      final raw = roundTrip([const DontFragmentAttr()]);
      final m = StunParser.parse(raw).value;
      expect(m.attribute<DontFragmentAttr>(), isNotNull);
    });

    test('ERROR-CODE 401 Unauthorized survives parse', () {
      final raw = roundTrip([
        const ErrorCodeAttr(code: 401, reason: 'Unauthorized'),
      ]);
      final m = StunParser.parse(raw).value;
      final err = m.attribute<ErrorCodeAttr>();
      expect(err?.code, 401);
      expect(err?.reason, 'Unauthorized');
    });

    test('compound TURN Allocate-style message', () {
      final raw = roundTrip([
        const RequestedTransportAttr(17),
        const LifetimeAttr(600),
        const DontFragmentAttr(),
        const UsernameAttr('alice'),
        const RealmAttr('example.org'),
        NonceAttr(Uint8List.fromList('deadbeef'.codeUnits)),
      ]);
      final m = StunParser.parse(raw).value;
      expect(m.attribute<RequestedTransportAttr>()?.protocol, 17);
      expect(m.attribute<LifetimeAttr>()?.seconds, 600);
      expect(m.attribute<DontFragmentAttr>(), isNotNull);
      expect(m.attribute<UsernameAttr>()?.username, 'alice');
      expect(m.attribute<RealmAttr>()?.realm, 'example.org');
      expect(m.attribute<NonceAttr>()?.nonce,
          Uint8List.fromList('deadbeef'.codeUnits));
    });
  });
}
