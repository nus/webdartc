import 'package:test/test.dart';
import 'package:webdartc/src/turn/state_machine.dart';

void main() {
  group('TurnServer.parse', () {
    test('turn: with explicit port + transport=udp', () {
      final s = TurnServer.parse(
        'turn:turn.example.org:3478?transport=udp',
        username: 'alice',
        credential: 'opensesame',
      )!;
      expect(s.host, 'turn.example.org');
      expect(s.port, 3478);
      expect(s.transport, 'udp');
      expect(s.secure, isFalse);
      expect(s.username, 'alice');
      expect(s.password, 'opensesame');
    });

    test('turn: defaults port to 3478 and transport to udp', () {
      final s = TurnServer.parse(
        'turn:turn.example.org',
        username: 'alice',
        credential: 'pw',
      )!;
      expect(s.port, 3478);
      expect(s.transport, 'udp');
      expect(s.secure, isFalse);
    });

    test('turns: defaults port to 5349 and transport to tcp', () {
      final s = TurnServer.parse(
        'turns:turn.example.org',
        username: 'alice',
        credential: 'pw',
      )!;
      expect(s.port, 5349);
      expect(s.transport, 'tcp');
      expect(s.secure, isTrue);
    });

    test('rejects stun: URIs', () {
      expect(
        TurnServer.parse('stun:stun.example.org',
            username: 'x', credential: 'y'),
        isNull,
      );
    });

    test('rejects missing credentials', () {
      expect(
        TurnServer.parse('turn:turn.example.org',
            username: null, credential: 'pw'),
        isNull,
      );
      expect(
        TurnServer.parse('turn:turn.example.org',
            username: 'u', credential: null),
        isNull,
      );
    });

    test('rejects malformed port', () {
      expect(
        TurnServer.parse('turn:turn.example.org:notaport',
            username: 'u', credential: 'p'),
        isNull,
      );
    });

    test('rejects empty host', () {
      expect(
        TurnServer.parse('turn:', username: 'u', credential: 'p'),
        isNull,
      );
    });

    test('IPv4 literal host', () {
      final s = TurnServer.parse(
        'turn:127.0.0.1:3478',
        username: 'test',
        credential: 'test',
      )!;
      expect(s.host, '127.0.0.1');
      expect(s.port, 3478);
    });
  });
}
