import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/src/core/ip_address.dart';

void main() {
  group('IpAddress.parse / tryParse', () {
    test('parses a dotted-quad IPv4 literal', () {
      final a = IpAddress.parse('192.168.1.5');
      expect(a.isV4, isTrue);
      expect(a.isV6, isFalse);
      expect(a.toBytes(), equals(Uint8List.fromList([192, 168, 1, 5])));
    });

    test('parses IPv6 literals and canonicalises (RFC 5952)', () {
      expect(IpAddress.parse('::1').toCanonical(), equals('::1'));
      expect(
        IpAddress.parse('0:0:0:0:0:0:0:1').toCanonical(),
        equals('::1'),
      );
      expect(
        IpAddress.parse('FE80:0:0:0:0:0:0:1').toCanonical(),
        equals('fe80::1'),
      );
    });

    test('IPv4-mapped IPv6 stays in 16-byte form', () {
      final a = IpAddress.parse('::ffff:127.0.0.1');
      expect(a.isV6, isTrue);
      expect(a.isV4, isFalse);
      expect(a.isIpv4MappedIpv6, isTrue);
      // not equal to the bare IPv4 form
      expect(a == IpAddress.parse('127.0.0.1'), isFalse);
    });

    test('tryParse returns null on invalid input', () {
      expect(IpAddress.tryParse(''), isNull);
      expect(IpAddress.tryParse('not.an.ip.really'), isNull);
      expect(IpAddress.tryParse('999.999.999.999'), isNull);
      expect(IpAddress.tryParse('example.com'), isNull); // hostnames rejected
    });

    test('parse throws FormatException on invalid input', () {
      expect(() => IpAddress.parse('garbage'), throwsFormatException);
    });
  });

  group('IpAddress.fromBytes', () {
    test('round-trips a 4-byte IPv4 address', () {
      final a = IpAddress.fromBytes(Uint8List.fromList([10, 0, 0, 1]));
      expect(a.toCanonical(), equals('10.0.0.1'));
    });

    test('round-trips a 16-byte IPv6 address', () {
      final bytes = Uint8List(16)..[15] = 1;
      expect(IpAddress.fromBytes(bytes).toCanonical(), equals('::1'));
    });

    test('rejects byte arrays of incorrect length', () {
      expect(
        () => IpAddress.fromBytes(Uint8List(0)),
        throwsArgumentError,
      );
      expect(
        () => IpAddress.fromBytes(Uint8List(8)),
        throwsArgumentError,
      );
    });

    test('defensively copies the input bytes', () {
      final src = Uint8List.fromList([1, 2, 3, 4]);
      final a = IpAddress.fromBytes(src);
      src[0] = 99;
      expect(a.toBytes()[0], equals(1));
    });
  });

  group('classification getters', () {
    test('isLoopback', () {
      expect(IpAddress.parse('127.0.0.1').isLoopback, isTrue);
      expect(IpAddress.parse('127.5.5.5').isLoopback, isTrue);
      expect(IpAddress.parse('128.0.0.1').isLoopback, isFalse);
      expect(IpAddress.parse('::1').isLoopback, isTrue);
      expect(IpAddress.parse('::2').isLoopback, isFalse);
    });

    test('isUnspecified', () {
      expect(IpAddress.parse('0.0.0.0').isUnspecified, isTrue);
      expect(IpAddress.parse('::').isUnspecified, isTrue);
      expect(IpAddress.parse('1.0.0.0').isUnspecified, isFalse);
      expect(IpAddress.parse('::1').isUnspecified, isFalse);
    });

    test('isLinkLocal', () {
      expect(IpAddress.parse('169.254.0.5').isLinkLocal, isTrue);
      expect(IpAddress.parse('169.254.255.255').isLinkLocal, isTrue);
      expect(IpAddress.parse('169.253.0.1').isLinkLocal, isFalse);
      expect(IpAddress.parse('168.254.0.1').isLinkLocal, isFalse);
      expect(IpAddress.parse('fe80::1').isLinkLocal, isTrue);
      expect(IpAddress.parse('febf::1').isLinkLocal, isTrue); // top of fe80::/10
      expect(IpAddress.parse('fec0::1').isLinkLocal, isFalse);
    });

    test('isIpv4MappedIpv6', () {
      expect(IpAddress.parse('::ffff:1.2.3.4').isIpv4MappedIpv6, isTrue);
      expect(IpAddress.parse('::1').isIpv4MappedIpv6, isFalse);
      expect(IpAddress.parse('1.2.3.4').isIpv4MappedIpv6, isFalse);
    });
  });

  group('equality and hashCode', () {
    test('two instances with the same canonical bytes are equal', () {
      final a = IpAddress.parse('192.168.1.5');
      final b = IpAddress.parse('192.168.1.5');
      expect(a == b, isTrue);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('different addresses are not equal', () {
      expect(
        IpAddress.parse('192.168.1.5') == IpAddress.parse('192.168.1.6'),
        isFalse,
      );
    });

    test('IPv4 and IPv4-mapped IPv6 are not equal', () {
      expect(
        IpAddress.parse('127.0.0.1') == IpAddress.parse('::ffff:127.0.0.1'),
        isFalse,
      );
    });

    test('IPv6 zero-compression variants are equal', () {
      final a = IpAddress.parse('fe80::1');
      final b = IpAddress.parse('fe80:0:0:0:0:0:0:1');
      expect(a == b, isTrue);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('works as a Map key', () {
      final m = <IpAddress, String>{
        IpAddress.parse('10.0.0.1'): 'a',
        IpAddress.parse('::1'): 'b',
      };
      expect(m[IpAddress.parse('10.0.0.1')], equals('a'));
      expect(m[IpAddress.parse('0:0:0:0:0:0:0:1')], equals('b'));
      expect(m[IpAddress.parse('10.0.0.2')], isNull);
    });
  });

  group('toBytes / immutability', () {
    test('toString returns the canonical text form', () {
      expect(IpAddress.parse('0:0:0:0:0:0:0:1').toString(), equals('::1'));
      expect(IpAddress.parse('192.168.1.5').toString(), equals('192.168.1.5'));
    });

    test('toBytes returns an unmodifiable view', () {
      final a = IpAddress.parse('10.0.0.1');
      final view = a.toBytes();
      expect(() => view[0] = 0, throwsUnsupportedError);
    });
  });
}
