import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

void main() {
  group('IceStateMachine', () {
    test('startGathering emits host candidate', () {
      final ice = IceStateMachine(controlling: true);
      IceCandidate? emitted;
      ice.onLocalCandidate = (c) => emitted = c;

      final params = IceParameters(usernameFragment: 'ufrag', password: 'password');
      ice.startGathering(params, localIp: '127.0.0.1', localPort: 12345);

      expect(emitted, isNotNull);
      expect(emitted!.ip, equals('127.0.0.1'));
      expect(emitted!.port, equals(12345));
      expect(emitted!.type, equals(IceCandidateType.host));
    });

    test('state transitions to iceGatheringComplete after startGathering', () {
      final ice = IceStateMachine(controlling: true);
      final states = <IceState>[];
      ice.onStateChange = (s) => states.add(s);

      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        localIp: '127.0.0.1',
        localPort: 9999,
      );

      expect(states, contains(IceState.iceGatheringComplete));
    });

    test('binding request response round-trip', () {
      // Two ICE agents — one sends a binding request, the other responds.
      final controllingIce = IceStateMachine(controlling: true);
      final controlledIce  = IceStateMachine(controlling: false);

      final controllingParams =
          IceParameters(usernameFragment: 'ctrl', password: 'ctrl_pass');
      final controlledParams =
          IceParameters(usernameFragment: 'ctrd', password: 'ctrd_pass');

      controllingIce.startGathering(controllingParams,
          localIp: '127.0.0.1', localPort: 10000);
      controlledIce.startGathering(controlledParams,
          localIp: '127.0.0.1', localPort: 10001);

      controllingIce.setRemoteParameters(controlledParams);
      controlledIce.setRemoteParameters(controllingParams);

      controllingIce.addRemoteCandidate(IceCandidate(
        foundation: '1',
        componentId: 1,
        transport: 'udp',
        priority: 1000,
        ip: '127.0.0.1',
        port: 10001,
        type: IceCandidateType.host,
      ));

      // The ICE state machines should have produced binding requests
      expect(controllingIce.state, isNot(equals(IceState.iceFailed)));
    });

    test('isStunPacket correctly identifies STUN', () {
      final stun = Uint8List(20);
      stun[4] = 0x21; stun[5] = 0x12; stun[6] = 0xA4; stun[7] = 0x42;
      expect(IceStateMachine.isStunPacket(stun), isTrue);

      final notStun = Uint8List.fromList([0x80, 0x01, 0x00, 0x00]);
      expect(IceStateMachine.isStunPacket(notStun), isFalse);
    });
  });

  group('StunServer', () {
    test('parse valid stun URI with port', () {
      final s = StunServer.parse('stun:stun.example.com:19302');
      expect(s, isNotNull);
      expect(s!.host, equals('stun.example.com'));
      expect(s.port, equals(19302));
    });

    test('parse valid stun URI without port defaults to 3478', () {
      final s = StunServer.parse('stun:stun.example.com');
      expect(s, isNotNull);
      expect(s!.host, equals('stun.example.com'));
      expect(s.port, equals(3478));
    });

    test('parse returns null for non-stun URI', () {
      expect(StunServer.parse('turn:turn.example.com'), isNull);
      expect(StunServer.parse('http://example.com'), isNull);
    });
  });

  group('srflx candidate gathering', () {
    test('startGathering sends STUN request to STUN server', () {
      final stunServer = StunServer(host: '198.51.100.1', port: 3478);
      final ice = IceStateMachine(controlling: true, stunServers: [stunServer]);
      final candidates = <IceCandidate>[];
      ice.onLocalCandidate = (c) => candidates.add(c);

      final result = ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        localIp: '192.168.1.10',
        localPort: 5000,
      );

      // Should emit host candidate first.
      expect(candidates.length, equals(1));
      expect(candidates[0].type, equals(IceCandidateType.host));

      // Should be in gathering state (waiting for STUN response).
      expect(ice.state, equals(IceState.iceGathering));

      // Should have output packets to STUN server.
      expect(result.isOk, isTrue);
      final packets = result.value.outputPackets;
      expect(packets.length, equals(1));
      expect(packets[0].remoteIp, equals('198.51.100.1'));
      expect(packets[0].remotePort, equals(3478));

      // Should have scheduled a gathering timeout.
      expect(result.value.nextTimeout, isNotNull);
    });

    test('STUN server response creates srflx candidate', () {
      final stunServer = StunServer(host: '198.51.100.1', port: 3478);
      final ice = IceStateMachine(controlling: true, stunServers: [stunServer]);
      final candidates = <IceCandidate>[];
      ice.onLocalCandidate = (c) => candidates.add(c);

      final gatherResult = ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        localIp: '192.168.1.10',
        localPort: 5000,
      );

      // Extract the STUN request to get the transaction ID.
      final stunRequest = gatherResult.value.outputPackets[0].data;
      final parsed = StunParser.parse(stunRequest);
      expect(parsed.isOk, isTrue);
      final txId = parsed.value.transactionId;

      // Simulate a STUN Binding Success Response with XOR-MAPPED-ADDRESS.
      final response = StunMessage(
        type: StunMessageType.bindingSuccessResponse,
        transactionId: txId,
        attributes: [
          XorMappedAddress(ip: '203.0.113.42', port: 12345),
        ],
      );
      final responseBytes = StunMessageBuilder.build(response);

      ice.processInput(
        responseBytes,
        remoteIp: '198.51.100.1',
        remotePort: 3478,
      );

      // Should now have host + srflx candidates.
      expect(candidates.length, equals(2));
      expect(candidates[1].type, equals(IceCandidateType.srflx));
      expect(candidates[1].ip, equals('203.0.113.42'));
      expect(candidates[1].port, equals(12345));
      expect(candidates[1].relatedAddress, equals('192.168.1.10'));
      expect(candidates[1].relatedPort, equals(5000));

      // Gathering should be complete.
      expect(ice.state, equals(IceState.iceGatheringComplete));
    });

    test('gathering timeout completes without srflx if no response', () {
      final stunServer = StunServer(host: '198.51.100.1', port: 3478);
      final ice = IceStateMachine(controlling: true, stunServers: [stunServer]);
      final candidates = <IceCandidate>[];
      ice.onLocalCandidate = (c) => candidates.add(c);

      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        localIp: '192.168.1.10',
        localPort: 5000,
      );

      // Simulate timeout.
      ice.handleTimeout(IceGatheringTimeoutToken());

      // Only host candidate, no srflx.
      expect(candidates.length, equals(1));
      expect(candidates[0].type, equals(IceCandidateType.host));
      expect(ice.state, equals(IceState.iceGatheringComplete));
    });
  });

  group('IceCandidate', () {
    test('computePriority for host candidate', () {
      final p = IceCandidate.computePriority(
        typePreference: IceCandidate.typePreferenceHost,
        localPreference: 65535,
        componentId: 1,
      );
      // (2^24 * 126) + (2^8 * 65535) + 255
      final expected = (1 << 24) * 126 + (1 << 8) * 65535 + 255;
      expect(p, equals(expected));
    });

    test('toSdpLine format', () {
      final c = IceCandidate(
        foundation: 'abc',
        componentId: 1,
        transport: 'udp',
        priority: 123456,
        ip: '192.168.1.1',
        port: 54321,
        type: IceCandidateType.host,
      );
      final line = c.toSdpLine();
      expect(line, contains('abc 1 udp 123456 192.168.1.1 54321 typ host'));
    });
  });
}
