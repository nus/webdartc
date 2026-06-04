import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('SctpStateMachine', () {
    test('connect sends INIT packet', () {
      final sctp = SctpStateMachine(isClient: true);
      final result = sctp.connect(remoteIp: IpAddress.parse('127.0.0.1'), remotePort: 5000);
      expect(result.isOk, isTrue);
      expect(result.value.outputPackets.length, equals(1));
      final pkt = result.value.outputPackets.first;
      // First chunk byte should be INIT type (0x01)
      expect(pkt.data[12], equals(0x01)); // chunk type INIT
    });

    test('client/server handshake completes', () {
      final client = SctpStateMachine(isClient: true);
      final server = SctpStateMachine(isClient: false);

      final clientIp = IpAddress.parse('127.0.0.1');
      final serverIp = IpAddress.parse('127.0.0.1');
      const clientPort = 5000;
      const serverPort = 5001;

      // Client sends INIT
      final initResult = client.connect(remoteIp: serverIp, remotePort: serverPort);
      expect(initResult.isOk, isTrue);
      final initPkt = initResult.value.outputPackets.first;

      // Server processes INIT → sends INIT-ACK
      final initAckResult = server.processInput(initPkt.data,
          remoteIp: clientIp, remotePort: clientPort);
      expect(initAckResult.isOk, isTrue);
      expect(initAckResult.value.outputPackets, isNotEmpty);
      final initAckPkt = initAckResult.value.outputPackets.first;
      // Chunk type INIT-ACK = 0x02
      expect(initAckPkt.data[12], equals(0x02));

      // Client processes INIT-ACK → sends COOKIE-ECHO
      final cookieEchoResult = client.processInput(initAckPkt.data,
          remoteIp: serverIp, remotePort: serverPort);
      expect(cookieEchoResult.isOk, isTrue);
      expect(cookieEchoResult.value.outputPackets, isNotEmpty);
      final cookieEchoPkt = cookieEchoResult.value.outputPackets.first;
      // Chunk type COOKIE-ECHO = 0x0A
      expect(cookieEchoPkt.data[12], equals(0x0A));

      // Server processes COOKIE-ECHO → sends COOKIE-ACK
      final cookieAckResult = server.processInput(cookieEchoPkt.data,
          remoteIp: clientIp, remotePort: clientPort);
      expect(cookieAckResult.isOk, isTrue);
      expect(cookieAckResult.value.outputPackets, isNotEmpty);
      final cookieAckPkt = cookieAckResult.value.outputPackets.first;
      // Chunk type COOKIE-ACK = 0x0B
      expect(cookieAckPkt.data[12], equals(0x0B));

      // Client processes COOKIE-ACK → established
      final finalResult = client.processInput(cookieAckPkt.data,
          remoteIp: serverIp, remotePort: serverPort);
      expect(finalResult.isOk, isTrue);
      expect(client.state.name, equals('established'));
    });

    test('sendData fails when not established', () {
      final sctp = SctpStateMachine(isClient: true);
      final result = sctp.sendData(
        data: Uint8List.fromList([1, 2, 3]),
        streamId: 0,
        ordered: true,
      );
      expect(result.isErr, isTrue);
    });

    test('empty message round-trips via Empty PPID + 1-byte padding', () {
      // RFC 8831 §6.6: an empty application message rides as a single
      // padding byte with a "WebRTC {String,Binary} Empty" PPID — a
      // zero-length SCTP DATA chunk is illegal (RFC 9260).
      final (client, server) = _establish();
      final delivered = <(Uint8List, bool)>[];
      server.onData =
          (int _, Uint8List data, bool isBinary) => delivered.add((data, isBinary));

      for (final ppid in [
        SctpPpid.webrtcStringEmpty,
        SctpPpid.webrtcBinaryEmpty,
      ]) {
        final out = client.sendData(
            data: Uint8List(0), streamId: 0, ordered: true, ppid: ppid);
        expect(out.isOk, isTrue);
        final pkt = out.value.outputPackets.single;
        // DATA chunk: 12-byte SCTP header + 16-byte chunk header, then the
        // user data. The chunk length field must cover one padding byte,
        // never a zero-length payload.
        final chunkLen = (pkt.data[14] << 8) | pkt.data[15];
        expect(chunkLen, 17, reason: 'chunk = 16 header + 1 padding byte');

        server.processInput(pkt.data,
            remoteIp: IpAddress.parse('127.0.0.1'), remotePort: 5000);
      }

      expect(delivered, hasLength(2));
      expect(delivered[0].$1, isEmpty); // string-empty delivered as empty
      expect(delivered[0].$2, isFalse);
      expect(delivered[1].$1, isEmpty); // binary-empty delivered as empty
      expect(delivered[1].$2, isTrue);
    });
  });

  group('DCEP', () {
    test('DcepOpenMessage encode/decode round-trip', () {
      final msg = DcepOpenMessage(
        channelType: DcepChannelType.reliable,
        label: 'test-channel',
        protocol: '',
      );
      final encoded = msg.encode();
      final decoded = DcepOpenMessage.parse(encoded);
      expect(decoded, isNotNull);
      expect(decoded!.label, equals('test-channel'));
      expect(decoded.channelType, equals(DcepChannelType.reliable));
    });
  });
}

/// Run the four-way SCTP handshake and return both ends in the
/// `established` state (client at port 5000, server at 5001).
(SctpStateMachine, SctpStateMachine) _establish() {
  final client = SctpStateMachine(isClient: true);
  final server = SctpStateMachine(isClient: false);
  final clientIp = IpAddress.parse('127.0.0.1');
  final serverIp = IpAddress.parse('127.0.0.1');
  const clientPort = 5000;
  const serverPort = 5001;

  final init = client.connect(remoteIp: serverIp, remotePort: serverPort);
  final initAck = server.processInput(init.value.outputPackets.first.data,
      remoteIp: clientIp, remotePort: clientPort);
  final cookieEcho = client.processInput(initAck.value.outputPackets.first.data,
      remoteIp: serverIp, remotePort: serverPort);
  final cookieAck = server.processInput(
      cookieEcho.value.outputPackets.first.data,
      remoteIp: clientIp,
      remotePort: clientPort);
  client.processInput(cookieAck.value.outputPackets.first.data,
      remoteIp: serverIp, remotePort: serverPort);
  return (client, server);
}
