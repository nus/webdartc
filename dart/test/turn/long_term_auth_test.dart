import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/stun/builder.dart';
import 'package:webdartc/src/stun/parser.dart';
import 'package:webdartc/src/stun/message.dart';
import 'package:webdartc/src/crypto/hmac_sha1.dart';
import 'package:webdartc/src/crypto/csprng.dart';

void main() {
  group('Long-term credential auth', () {
    test('longTermKey matches RFC 5389 §15.4 MD5 derivation', () {
      // Verified out-of-band:
      //   printf 'alice:example.org:opensesame' | md5
      //   84c21a1eea070a19768404a4046a8787
      final key = StunMessageBuilder.longTermKey(
          'alice', 'example.org', 'opensesame');
      expect(key.length, 16);
      expect(
        key,
        Uint8List.fromList([
          0x84, 0xc2, 0x1a, 0x1e, 0xea, 0x07, 0x0a, 0x19,
          0x76, 0x84, 0x04, 0xa4, 0x04, 0x6a, 0x87, 0x87,
        ]),
      );
    });

    test('buildWithIntegrity(fingerprint: false) omits FINGERPRINT but '
        'keeps MESSAGE-INTEGRITY', () {
      final key = StunMessageBuilder.longTermKey('u', 'r', 'p');
      final msg = StunMessage(
        type: StunMessageType.allocateRequest,
        transactionId: Csprng.randomBytes(12),
        attributes: [
          const RequestedTransportAttr(17),
          const UsernameAttr('u'),
          const RealmAttr('r'),
          NonceAttr(Uint8List.fromList('nonce0'.codeUnits)),
        ],
      );
      final raw =
          StunMessageBuilder.buildWithIntegrity(msg, key, fingerprint: false);
      final parsed = StunParser.parse(raw).value;
      expect(parsed.attribute<MessageIntegrityAttr>(), isNotNull);
      expect(parsed.attribute<FingerprintAttr>(), isNull);
    });

    test('buildWithIntegrity(fingerprint: true) keeps both', () {
      final key = StunMessageBuilder.longTermKey('u', 'r', 'p');
      final msg = StunMessage(
        type: StunMessageType.bindingRequest,
        transactionId: Csprng.randomBytes(12),
        attributes: [const UsernameAttr('u')],
      );
      final raw = StunMessageBuilder.buildWithIntegrity(msg, key);
      final parsed = StunParser.parse(raw).value;
      expect(parsed.attribute<MessageIntegrityAttr>(), isNotNull);
      expect(parsed.attribute<FingerprintAttr>(), isNotNull);
    });

    test('MESSAGE-INTEGRITY verifies with the long-term key', () {
      final key = StunMessageBuilder.longTermKey('alice', 'example.org', 'pw');
      final msg = StunMessage(
        type: StunMessageType.allocateRequest,
        transactionId: Csprng.randomBytes(12),
        attributes: [
          const RequestedTransportAttr(17),
          const UsernameAttr('alice'),
          const RealmAttr('example.org'),
          NonceAttr(Uint8List.fromList('n123'.codeUnits)),
        ],
      );
      final raw =
          StunMessageBuilder.buildWithIntegrity(msg, key, fingerprint: false);

      // Reconstruct the HMAC input: the header (with length adjusted to
      // include MESSAGE-INTEGRITY) plus everything before MESSAGE-INTEGRITY.
      final parsed = StunParser.parse(raw).value;
      final mac = parsed.attribute<MessageIntegrityAttr>()!.hmac;
      expect(mac.length, 20);

      // Locate MESSAGE-INTEGRITY in the raw buffer and check the HMAC
      // covers the header (length pre-set to "up through integrity") +
      // attribute bytes before it. Walking attributes is simpler than
      // re-running the encoder.
      final integrityOffset = raw.length - 24; // 4 attr header + 20 hmac
      final forHmac = Uint8List(integrityOffset);
      forHmac.setRange(0, integrityOffset, raw);
      // The wire-format length already includes the integrity attribute
      // since the builder set it that way before computing the HMAC, so
      // no header rewrite is needed.
      expect(HmacSha1.verify(key, forHmac, mac), isTrue);
    });
  });
}
