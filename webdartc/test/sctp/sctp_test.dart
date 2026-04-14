import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('SctpStateMachine', () {
    test('connect sends INIT packet', () {
      final sctp = SctpStateMachine(isClient: true);
      final result = sctp.connect(remoteIp: '127.0.0.1', remotePort: 5000);
      expect(result.isOk, isTrue);
      expect(result.value.outputPackets.length, equals(1));
      final pkt = result.value.outputPackets.first;
      // First chunk byte should be INIT type (0x01)
      expect(pkt.data[12], equals(0x01)); // chunk type INIT
    });

    test('client/server handshake completes', () {
      final client = SctpStateMachine(isClient: true);
      final server = SctpStateMachine(isClient: false);

      const clientIp = '127.0.0.1';
      const serverIp = '127.0.0.1';
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
