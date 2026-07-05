/// Characterization tests pinning IpAddress parse / canonicalization /
/// loopback behavior. Written against the original `dart:io`
/// InternetAddress-backed implementation (values captured on macOS, whose
/// formatter is the classic BSD inet_ntop) before ip_address.dart was
/// reimplemented in pure Dart, so the swap is provably behavior-preserving.
library;

import 'package:test/test.dart';
import 'package:webdartc/src/core/ip_address.dart';

void main() {
  group('IPv6 canonical form (RFC 5952 / BSD inet_ntop rules)', () {
    const cases = <String, String>{
      // Basic compression, lowercase hex.
      '::': '::',
      '::1': '::1',
      '1::': '1::',
      '2001:db8::1': '2001:db8::1',
      '2001:0DB8:0000:0000:0000:FF00:0042:8329': '2001:db8::ff00:42:8329',
      'fe80::1': 'fe80::1',
      // Longest zero run wins…
      '1:0:0:1:0:0:0:1': '1:0:0:1::1',
      '1:0:0:0:2:0:0:3': '1::2:0:0:3',
      '2001:db8:0:1:0:0:0:1': '2001:db8:0:1::1',
      '2001:0:0:1:0:0:0:1': '2001:0:0:1::1',
      // …leftmost on ties…
      '1:0:2:0:0:3:0:0': '1:0:2::3:0:0',
      // …and a single zero group is never compressed.
      '0:1:2:3:4:5:6:7': '0:1:2:3:4:5:6:7',
      '1:2:3:4:5:6:7:0': '1:2:3:4:5:6:7:0',
      // IPv4-mapped/-embedded tails: dotted only for the inet_ntop special
      // cases — a zero run covering exactly the first six groups (::/96
      // with both low groups in play) or five groups + ffff (::ffff:0:0/96).
      '::ffff:192.168.1.5': '::ffff:192.168.1.5',
      '::ffff:127.0.0.1': '::ffff:127.0.0.1',
      '::ffff:0:0': '::ffff:0.0.0.0',
      '::0.0.0.1': '::1',
      '::0.0.1.0': '::100',
      '::1.2.3.4': '::1.2.3.4',
      '64:ff9b::1.2.3.4': '64:ff9b::102:304',
      '1:2:3:4:5:6:1.2.3.4': '1:2:3:4:5:6:102:304',
      // Full form collapses.
      '0:0:0:0:0:0:0:1': '::1',
      // Zone IDs are dropped by parsing.
      'fe80::1%en0': 'fe80::1',
    };
    cases.forEach((input, canonical) {
      test('$input -> $canonical', () {
        expect(IpAddress.parse(input).toCanonical(), canonical);
      });
    });
  });

  group('IPv4 parse quirks', () {
    test('leading zeros are accepted and normalized away', () {
      expect(IpAddress.parse('01.2.3.4').toCanonical(), '1.2.3.4');
      expect(IpAddress.parse('00.0.0.0').toCanonical(), '0.0.0.0');
      expect(IpAddress.parse('1.2.3.04').toCanonical(), '1.2.3.4');
      expect(IpAddress.parse('::ffff:01.2.3.4').toCanonical(),
          '::ffff:1.2.3.4');
    });

    test('malformed literals are rejected', () {
      for (final bad in [
        '1.2.3', '1.2.3.4.5', '256.1.1.1', ' 1.2.3.4', '1.2.3.4 ',
        '1.2.3.-4', '1.2.3.4%x',
        ':::', '12345::', 'g::1', '1:2:3:4:5:6:7', '1::2::3',
        ':1:2:3:4:5:6:7', '1:2:3:4:5:6:7:', '1:2:3:4:5:6:7:8:9',
      ]) {
        expect(IpAddress.tryParse(bad), isNull, reason: bad);
      }
    });
  });

  group('isLoopback', () {
    test('IPv4: 127.0.0.0/8', () {
      expect(IpAddress.parse('127.0.0.1').isLoopback, isTrue);
      expect(IpAddress.parse('127.255.255.255').isLoopback, isTrue);
      expect(IpAddress.parse('126.0.0.1').isLoopback, isFalse);
      expect(IpAddress.parse('128.0.0.1').isLoopback, isFalse);
    });

    test('IPv6: exactly ::1 (IPv4-mapped 127/8 is NOT loopback)', () {
      expect(IpAddress.parse('::1').isLoopback, isTrue);
      expect(IpAddress.parse('::0.0.0.1').isLoopback, isTrue);
      expect(IpAddress.parse('::2').isLoopback, isFalse);
      expect(IpAddress.parse('::').isLoopback, isFalse);
      expect(IpAddress.parse('::ffff:127.0.0.1').isLoopback, isFalse);
      expect(IpAddress.parse('fe80::1').isLoopback, isFalse);
    });
  });
}
