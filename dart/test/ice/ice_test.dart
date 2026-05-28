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
      ice.startGathering(params, hosts: [(ip: IpAddress.parse('127.0.0.1'), port: 12345)]);

      expect(emitted, isNotNull);
      expect(emitted!.ip, equals(IpAddress.parse('127.0.0.1')));
      expect(emitted!.port, equals(12345));
      expect(emitted!.type, equals(IceCandidateType.host));
    });

    test('state transitions to iceGatheringComplete after startGathering', () {
      final ice = IceStateMachine(controlling: true);
      final states = <IceState>[];
      ice.onStateChange = (s) => states.add(s);

      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        hosts: [(ip: IpAddress.parse('127.0.0.1'), port: 9999)],
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
          hosts: [(ip: IpAddress.parse('127.0.0.1'), port: 10000)]);
      controlledIce.startGathering(controlledParams,
          hosts: [(ip: IpAddress.parse('127.0.0.1'), port: 10001)]);

      controllingIce.setRemoteParameters(controlledParams);
      controlledIce.setRemoteParameters(controllingParams);

      controllingIce.addRemoteCandidate(IceCandidate(
        foundation: '1',
        componentId: 1,
        transport: 'udp',
        priority: 1000,
        ip: IpAddress.parse('127.0.0.1'),
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
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
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
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
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
          XorMappedAddress(
            address: IpAddress.parse('203.0.113.42'),
            port: 12345,
          ),
        ],
      );
      final responseBytes = StunMessageBuilder.build(response);

      ice.processInput(
        responseBytes,
        remoteIp: IpAddress.parse('198.51.100.1'),
        remotePort: 3478,
      );

      // Should now have host + srflx candidates.
      expect(candidates.length, equals(2));
      expect(candidates[1].type, equals(IceCandidateType.srflx));
      expect(candidates[1].ip, equals(IpAddress.parse('203.0.113.42')));
      expect(candidates[1].port, equals(12345));
      expect(candidates[1].relatedAddress, equals(IpAddress.parse('192.168.1.10')));
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
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
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
        ip: IpAddress.parse('192.168.1.1'),
        port: 54321,
        type: IceCandidateType.host,
      );
      final line = c.toSdpLine();
      expect(line, contains('abc 1 udp 123456 192.168.1.1 54321 typ host'));
    });

    test('addLocalRelayCandidate emits a relay candidate with raddr/rport',
        () {
      final ice = IceStateMachine(controlling: true);
      final emitted = <IceCandidate>[];
      ice.onLocalCandidate = emitted.add;

      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
      );
      emitted.clear();

      final res = ice.addLocalRelayCandidate(
        relayedIp: IpAddress.parse('203.0.113.7'),
        relayedPort: 49152,
        relatedAddress: IpAddress.parse('192.168.1.10'),
        relatedPort: 5000,
      );
      expect(res.isOk, isTrue);

      expect(emitted, hasLength(1));
      final c = emitted.single;
      expect(c.type, IceCandidateType.relay);
      expect(c.ip.toCanonical(), '203.0.113.7');
      expect(c.port, 49152);
      expect(c.relatedAddress?.toCanonical(), '192.168.1.10');
      expect(c.relatedPort, 5000);
      // Relay candidates use type-pref 0 per RFC 8445 §5.1.2.2.
      // Encoded into the priority's top byte.
      expect((c.priority >> 24) & 0xFF, IceCandidate.typePreferenceRelay);
      // SDP line contains the candidate type + raddr/rport.
      final sdp = c.toSdpLine();
      expect(sdp, contains('typ relay'));
      expect(sdp, contains('raddr 192.168.1.10 rport 5000'));
    });
  });

  group('IceTransportPolicy.relay', () {
    test('startGathering does not emit a host candidate', () {
      final ice = IceStateMachine(controlling: true, relayOnly: true);
      final emitted = <IceCandidate>[];
      ice.onLocalCandidate = emitted.add;

      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
      );

      expect(emitted, isEmpty);
    });

    test('startGathering does not send STUN binding requests for srflx', () {
      final ice = IceStateMachine(
        controlling: true,
        stunServers: const [StunServer(host: '203.0.113.1', port: 3478)],
        relayOnly: true,
      );
      final res = ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
      );
      expect(res.isOk, isTrue);
      expect(res.value.outputPackets, isEmpty);
    });

    test('relay-only still emits relay candidates from TURN allocations', () {
      final ice = IceStateMachine(controlling: true, relayOnly: true);
      final emitted = <IceCandidate>[];
      ice.onLocalCandidate = emitted.add;

      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
      );

      final res = ice.addLocalRelayCandidate(
        relayedIp: IpAddress.parse('203.0.113.7'),
        relayedPort: 49152,
        relatedAddress: IpAddress.parse('192.168.1.10'),
        relatedPort: 5000,
      );
      expect(res.isOk, isTrue);
      expect(emitted, hasLength(1));
      expect(emitted.single.type, IceCandidateType.relay);
    });

    test('host and srflx remotes do not form a pair but relay does', () {
      // Set up a relay-only ICE with one local relay + remote params so
      // any accepted remote will trigger a connectivity check.
      final ice = IceStateMachine(controlling: true, relayOnly: true);
      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
      );
      ice.addLocalRelayCandidate(
        relayedIp: IpAddress.parse('203.0.113.7'),
        relayedPort: 49152,
        relatedAddress: IpAddress.parse('192.168.1.10'),
        relatedPort: 5000,
      );
      ice.setRemoteParameters(
          IceParameters(usernameFragment: 'r', password: 'rp'));

      IceCandidate make(IceCandidateType type, String ip, int port) =>
          IceCandidate(
            foundation: 'f',
            componentId: 1,
            transport: 'udp',
            priority: 1,
            ip: IpAddress.parse(ip),
            port: port,
            type: type,
          );

      // Host and srflx remotes are silently dropped: ProcessResult.empty.
      final h = ice.addRemoteCandidate(make(
          IceCandidateType.host, '10.0.0.5', 30000));
      expect(h.isOk, isTrue);
      expect(h.value.outputPackets, isEmpty);

      final s = ice.addRemoteCandidate(make(
          IceCandidateType.srflx, '198.51.100.1', 30001));
      expect(s.isOk, isTrue);
      expect(s.value.outputPackets, isEmpty);

      // Relay remote pairs with our local relay → triggers a STUN check.
      final r = ice.addRemoteCandidate(make(
          IceCandidateType.relay, '203.0.113.99', 49200));
      expect(r.isOk, isTrue);
      expect(r.value.outputPackets, isNotEmpty);
    });
  });

  group('IceStateMachine._addPair dedup', () {
    test('adding the same remote twice yields only one pair', () {
      // Trickle-ICE callers can drive `addRemoteCandidate` for the
      // same candidate twice in races between the initial pairing
      // and the subsequent `setRemoteParameters` → `_startChecks`
      // walk. The state machine must keep the check list unique.
      final ice = IceStateMachine(controlling: true);
      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
      );

      final remote = IceCandidate(
        foundation: 'r1',
        componentId: 1,
        transport: 'udp',
        priority: 1,
        ip: IpAddress.parse('203.0.113.1'),
        port: 30000,
        type: IceCandidateType.host,
      );
      ice.addRemoteCandidate(remote);
      ice.addRemoteCandidate(remote);
      // Setting params triggers `_startChecks`, which re-walks
      // `_remoteCandidates`; this is a third opportunity to add the
      // pair. Dedup must still produce one pair.
      ice.setRemoteParameters(
          IceParameters(usernameFragment: 'r', password: 'rp'));

      final remoteCoordPairs = ice.pairs.where(
          (p) => p.remote.ip == remote.ip && p.remote.port == remote.port);
      expect(remoteCoordPairs, hasLength(1));
    });

    test('different remote types at same address are kept as distinct pairs',
        () {
      // Host and prflx with the same (ip, port) are RFC-distinct
      // candidates (different priorities, different selection
      // semantics). They must NOT be coalesced by the dedup.
      final ice = IceStateMachine(controlling: true);
      ice.startGathering(
        IceParameters(usernameFragment: 'u', password: 'p'),
        hosts: [(ip: IpAddress.parse('192.168.1.10'), port: 5000)],
      );

      final host = IceCandidate(
        foundation: 'h',
        componentId: 1,
        transport: 'udp',
        priority: 1,
        ip: IpAddress.parse('203.0.113.1'),
        port: 30000,
        type: IceCandidateType.host,
      );
      final prflx = IceCandidate(
        foundation: 'p',
        componentId: 1,
        transport: 'udp',
        priority: 1,
        ip: IpAddress.parse('203.0.113.1'),
        port: 30000,
        type: IceCandidateType.prflx,
      );
      ice.addRemoteCandidate(host);
      ice.addRemoteCandidate(prflx);

      final samePort = ice.pairs
          .where((p) => p.remote.port == 30000)
          .map((p) => p.remote.type)
          .toSet();
      expect(samePort, equals({IceCandidateType.host, IceCandidateType.prflx}));
    });
  });
}
