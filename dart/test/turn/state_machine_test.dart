import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/core/state_machine.dart' show ParseError;
import 'package:webdartc/turn/channel_data.dart';
import 'package:webdartc/turn/state_machine.dart';
import 'package:webdartc/webdartc.dart';

final _serverIp = IpAddress.parse('127.0.0.1');
const _serverPort = 3478;
final _peerIp = IpAddress.parse('192.0.2.42');
const _peerPort = 5000;
final _relayedIp = IpAddress.parse('203.0.113.7');
const _relayedPort = 49152;

TurnAllocation _newAlloc({String username = 'alice', String password = 'pw'}) =>
    TurnAllocation(
      serverIp: _serverIp,
      serverPort: _serverPort,
      username: username,
      password: password,
    );

/// Helper: parse an outgoing OutputPacket as a STUN message.
StunMessage _stun(OutputPacket pkt) => StunParser.parse(pkt.data).value;

/// Build a synthetic server response for round-trip tests.
Uint8List _serverResponse(int type, Uint8List txId, List<StunAttribute> attrs) =>
    StunMessageBuilder.build(StunMessage(
      type: type,
      transactionId: txId,
      attributes: attrs,
    ));

/// Build an authenticated server response — server doesn't actually need
/// to sign, but coturn does include MESSAGE-INTEGRITY on success
/// responses. We don't verify it on the client (RFC 5389 §10.1.2 says
/// it's optional for the client to check), so we just include it via
/// the same long-term key the client would derive.
Uint8List _serverAuthResponse(
  int type,
  Uint8List txId,
  List<StunAttribute> attrs, {
  required String username,
  required String realm,
  required String password,
}) {
  final key = StunMessageBuilder.longTermKey(username, realm, password);
  return StunMessageBuilder.buildWithIntegrity(
      StunMessage(type: type, transactionId: txId, attributes: attrs), key,
      fingerprint: false);
}

void main() {
  group('TURN allocation: bootstrap', () {
    test('start emits unauthenticated Allocate', () {
      final a = _newAlloc();
      final res = a.start();
      expect(res.isOk, isTrue);
      expect(a.state, TurnState.allocating);
      expect(res.value.outputPackets, hasLength(1));
      final msg = _stun(res.value.outputPackets.single);
      expect(msg.type, StunMessageType.allocateRequest);
      expect(msg.attribute<RequestedTransportAttr>()?.protocol,
          turnRequestedTransportUdp);
      expect(msg.attribute<LifetimeAttr>()?.seconds,
          turnDefaultLifetimeSeconds);
      // No auth on the first round.
      expect(msg.attribute<UsernameAttr>(), isNull);
      expect(msg.attribute<MessageIntegrityAttr>(), isNull);
    });

    test('start rejected outside idle', () {
      final a = _newAlloc();
      a.start();
      final res = a.start();
      expect(res.isErr, isTrue);
    });

    test('401 triggers re-Allocate with USERNAME + REALM + NONCE + '
        'MESSAGE-INTEGRITY', () {
      final a = _newAlloc(username: 'alice', password: 'pw');
      final firstAllocate = _stun(a.start().value.outputPackets.single);

      final challenge = _serverResponse(
        StunMessageType.allocateErrorResponse,
        firstAllocate.transactionId,
        [
          const ErrorCodeAttr(code: StunErrorCode.unauthorized, reason: 'Unauthorized'),
          const RealmAttr('example.org'),
          NonceAttr(Uint8List.fromList('n1'.codeUnits)),
        ],
      );
      final res = a.processInput(challenge,
          remoteIp: _serverIp, remotePort: _serverPort);
      expect(res.isOk, isTrue);
      expect(a.state, TurnState.authenticating);
      expect(res.value.outputPackets, hasLength(1));
      final retry = _stun(res.value.outputPackets.single);
      expect(retry.type, StunMessageType.allocateRequest);
      expect(retry.attribute<UsernameAttr>()?.username, 'alice');
      expect(retry.attribute<RealmAttr>()?.realm, 'example.org');
      expect(retry.attribute<NonceAttr>()?.nonce,
          Uint8List.fromList('n1'.codeUnits));
      expect(retry.attribute<MessageIntegrityAttr>(), isNotNull);
      expect(retry.attribute<FingerprintAttr>(), isNull);
    });

    test('Allocate success transitions to allocated and schedules refresh',
        () {
      final a = _newAlloc();
      var allocatedCalls = 0;
      a.onAllocated = (ip, port) {
        allocatedCalls++;
        expect(ip.toCanonical(), _relayedIp.toCanonical());
        expect(port, _relayedPort);
      };
      _runAuthFlow(a);

      expect(a.state, TurnState.allocated);
      expect(allocatedCalls, 1);
      expect(a.relayedAddress?.toCanonical(), _relayedIp.toCanonical());
      expect(a.relayedPort, _relayedPort);
      expect(a.grantedLifetime, turnDefaultLifetimeSeconds);
    });

    test('Allocate error other than 401/438 ends the allocation', () {
      final a = _newAlloc();
      var failureReason = '';
      a.onAllocationFailed = (r) => failureReason = r;
      final first = _stun(a.start().value.outputPackets.single);

      final reject = _serverResponse(
        StunMessageType.allocateErrorResponse,
        first.transactionId,
        [
          const ErrorCodeAttr(
              code: StunErrorCode.allocationMismatch,
              reason: 'Allocation Mismatch'),
        ],
      );
      a.processInput(reject, remoteIp: _serverIp, remotePort: _serverPort);
      expect(a.state, TurnState.closed);
      expect(failureReason, contains('${StunErrorCode.allocationMismatch}'));
    });
  });

  group('TURN allocation: CreatePermission', () {
    test('createPermission requires allocated state', () {
      final a = _newAlloc();
      expect(a.createPermission(_peerIp).isErr, isTrue);
    });

    test('CreatePermission success registers the peer + schedules refresh',
        () {
      final a = _newAlloc();
      _runAuthFlow(a);

      var granted = false;
      a.onPermissionResult = (ip, ok) {
        if (ip == _peerIp) granted = ok;
      };
      final req = a.createPermission(_peerIp).value;
      expect(req.outputPackets, hasLength(1));
      final reqMsg = _stun(req.outputPackets.single);
      expect(reqMsg.type, StunMessageType.createPermissionRequest);
      expect(reqMsg.attribute<XorPeerAddress>()?.address.toCanonical(),
          _peerIp.toCanonical());

      final res = a.processInput(
          _serverResponse(StunMessageType.createPermissionSuccessResponse,
              reqMsg.transactionId, []),
          remoteIp: _serverIp,
          remotePort: _serverPort);
      expect(res.isOk, isTrue);
      expect(a.hasPermission(_peerIp), isTrue);
      expect(granted, isTrue);
      expect(res.value.nextTimeout?.token,
          isA<TurnPermissionRefreshToken>());
    });

    test('CreatePermission failure does not register the peer', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      var notified = true;
      a.onPermissionResult = (_, ok) => notified = ok;
      final req = a.createPermission(_peerIp).value;
      final reqTxId = _stun(req.outputPackets.single).transactionId;

      a.processInput(
        _serverResponse(
          StunMessageType.createPermissionErrorResponse,
          reqTxId,
          [
            const ErrorCodeAttr(
                code: StunErrorCode.forbidden, reason: 'Forbidden'),
          ],
        ),
        remoteIp: _serverIp,
        remotePort: _serverPort,
      );
      expect(a.hasPermission(_peerIp), isFalse);
      expect(notified, isFalse);
    });
  });

  group('TURN allocation: ChannelBind', () {
    test('bindChannel assigns a channel in the application range', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      final req = a.bindChannel(_peerIp, _peerPort).value;
      final reqMsg = _stun(req.outputPackets.single);
      expect(reqMsg.type, StunMessageType.channelBindRequest);
      final channel = reqMsg.attribute<ChannelNumberAttr>()!.channel;
      expect(channel, greaterThanOrEqualTo(channelNumberMin));
      expect(channel, lessThanOrEqualTo(channelNumberMax));
      expect(reqMsg.attribute<XorPeerAddress>()?.port, _peerPort);
    });

    test('ChannelBind success records the channel + grants permission '
        'implicitly', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      int? boundChannel;
      a.onChannelResult = (ch, _, _, ok) {
        if (ok) boundChannel = ch;
      };
      final req = a.bindChannel(_peerIp, _peerPort).value;
      final reqTxId = _stun(req.outputPackets.single).transactionId;

      final res = a.processInput(
          _serverResponse(StunMessageType.channelBindSuccessResponse,
              reqTxId, []),
          remoteIp: _serverIp,
          remotePort: _serverPort);
      final channel = a.channelFor(_peerIp, _peerPort);
      expect(channel, isNotNull);
      expect(boundChannel, channel);
      expect(a.hasPermission(_peerIp), isTrue);
      expect(res.value.nextTimeout?.token, isA<TurnChannelRefreshToken>());
    });

    test('ChannelBind error clears the optimistic assignment', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      var notified = true;
      a.onChannelResult = (_, _, _, ok) => notified = ok;
      final req = a.bindChannel(_peerIp, _peerPort).value;
      final reqTxId = _stun(req.outputPackets.single).transactionId;

      a.processInput(
        _serverResponse(
          StunMessageType.channelBindErrorResponse,
          reqTxId,
          [
            const ErrorCodeAttr(
                code: StunErrorCode.badRequest, reason: 'Bad Request'),
          ],
        ),
        remoteIp: _serverIp,
        remotePort: _serverPort,
      );
      expect(a.channelFor(_peerIp, _peerPort), isNull);
      expect(notified, isFalse);
    });
  });

  group('TURN allocation: wrapSend dispatch', () {
    test('Send indication path when no channel is bound', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      // Grant permission so wrapSend accepts.
      final permReq = a.createPermission(_peerIp).value;
      final permTx = _stun(permReq.outputPackets.single).transactionId;
      a.processInput(
        _serverResponse(StunMessageType.createPermissionSuccessResponse,
            permTx, []),
        remoteIp: _serverIp,
        remotePort: _serverPort,
      );

      final payload = Uint8List.fromList([1, 2, 3, 4, 5]);
      final out = a.wrapSend(_peerIp, _peerPort, payload).value;
      // Destined to the TURN server, not the peer directly.
      expect(out.remoteIp, _serverIp.toCanonical());
      expect(out.remotePort, _serverPort);
      final msg = StunParser.parse(out.data).value;
      expect(msg.type, StunMessageType.sendIndication);
      expect(msg.attribute<XorPeerAddress>()?.address.toCanonical(),
          _peerIp.toCanonical());
      expect(msg.attribute<DataAttr>()?.data, payload);
    });

    test('ChannelData path when a channel is bound', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      final req = a.bindChannel(_peerIp, _peerPort).value;
      final reqTx = _stun(req.outputPackets.single).transactionId;
      a.processInput(
        _serverResponse(StunMessageType.channelBindSuccessResponse, reqTx, []),
        remoteIp: _serverIp,
        remotePort: _serverPort,
      );

      final payload = Uint8List.fromList([10, 20, 30, 40]);
      final out = a.wrapSend(_peerIp, _peerPort, payload).value;
      expect(isChannelData(out.data), isTrue);
      final frame = parseChannelData(out.data)!;
      expect(frame.channel, a.channelFor(_peerIp, _peerPort));
      expect(frame.payload, payload);
    });

    test('wrapSend without permission fails', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      expect(
          a.wrapSend(_peerIp, _peerPort, Uint8List(4)).isErr, isTrue);
    });

    test('wrapSend before allocated fails', () {
      final a = _newAlloc();
      expect(
          a.wrapSend(_peerIp, _peerPort, Uint8List(0)).isErr, isTrue);
    });
  });

  group('TURN allocation: receive', () {
    test('DataIndication invokes onPeerData', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      late IpAddress receivedIp;
      late int receivedPort;
      late Uint8List receivedPayload;
      a.onPeerData = (ip, port, p) {
        receivedIp = ip;
        receivedPort = port;
        receivedPayload = p;
      };
      final pkt = _serverResponse(
        StunMessageType.dataIndication,
        Csprng.randomBytes(12),
        [
          XorPeerAddress(address: _peerIp, port: _peerPort),
          DataAttr(Uint8List.fromList([7, 7, 7])),
        ],
      );
      a.processInput(pkt, remoteIp: _serverIp, remotePort: _serverPort);
      expect(receivedIp.toCanonical(), _peerIp.toCanonical());
      expect(receivedPort, _peerPort);
      expect(receivedPayload, Uint8List.fromList([7, 7, 7]));
    });

    test('ChannelData invokes onPeerData with the channel\'s peer', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      // Bind channel first so the channel→peer table is populated.
      final req = a.bindChannel(_peerIp, _peerPort).value;
      final reqTx = _stun(req.outputPackets.single).transactionId;
      a.processInput(
        _serverResponse(
            StunMessageType.channelBindSuccessResponse, reqTx, []),
        remoteIp: _serverIp,
        remotePort: _serverPort,
      );
      final channel = a.channelFor(_peerIp, _peerPort)!;

      late Uint8List received;
      a.onPeerData = (_, _, p) => received = p;
      final payload = Uint8List.fromList([100, 200, 50]);
      a.processInput(buildChannelData(channel, payload),
          remoteIp: _serverIp, remotePort: _serverPort);
      expect(received, payload);
    });

    test('packet from non-server is rejected', () {
      final a = _newAlloc();
      final res = a.processInput(Uint8List(20),
          remoteIp: IpAddress.parse('10.0.0.1'), remotePort: 9999);
      expect(res.isErr, isTrue);
    });
  });

  group('TURN allocation: Refresh + close + stale-nonce', () {
    test('handleTimeout(TurnRefreshToken) sends authenticated Refresh', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      final res = a.handleTimeout(TurnRefreshToken());
      expect(res.isOk, isTrue);
      final msg = _stun(res.value.outputPackets.single);
      expect(msg.type, StunMessageType.refreshRequest);
      expect(msg.attribute<MessageIntegrityAttr>(), isNotNull);
      expect(msg.attribute<LifetimeAttr>()?.seconds, turnDefaultLifetimeSeconds);
    });

    test('close() sends Refresh(0) and closed callback fires on success',
        () {
      final a = _newAlloc();
      _runAuthFlow(a);
      var closed = false;
      a.onClosed = () => closed = true;

      final close = a.close().value;
      expect(a.state, TurnState.closing);
      final refresh = _stun(close.outputPackets.single);
      expect(refresh.attribute<LifetimeAttr>()?.seconds, 0);

      a.processInput(
        _serverResponse(StunMessageType.refreshSuccessResponse,
            refresh.transactionId, [const LifetimeAttr(0)]),
        remoteIp: _serverIp,
        remotePort: _serverPort,
      );
      expect(a.state, TurnState.closed);
      expect(closed, isTrue);
    });

    test('438 Stale Nonce on Allocate retry picks up the new nonce', () {
      final a = _newAlloc();
      final retryTx = _runAuthRetry(a);
      final after = a
          .processInput(
            _serverResponse(StunMessageType.allocateErrorResponse, retryTx, [
              const ErrorCodeAttr(code: StunErrorCode.staleNonce, reason: 'Stale Nonce'),
              const RealmAttr('example.org'),
              NonceAttr(Uint8List.fromList('n2'.codeUnits)),
            ]),
            remoteIp: _serverIp,
            remotePort: _serverPort,
          )
          .value;
      final next = _stun(after.outputPackets.single);
      expect(next.attribute<NonceAttr>()?.nonce,
          Uint8List.fromList('n2'.codeUnits));
    });

    test('close() outside allocated returns Err', () {
      final a = _newAlloc();
      expect(a.close().isErr, isTrue);
    });

    test('handleTimeout(TurnRefreshToken) is a no-op when not allocated',
        () {
      final a = _newAlloc();
      final res = a.handleTimeout(TurnRefreshToken());
      expect(res.isOk, isTrue);
      expect(res.value.outputPackets, isEmpty);
    });

    test('401 missing REALM/NONCE is a ParseError', () {
      final a = _newAlloc();
      final firstTx = _stun(a.start().value.outputPackets.single).transactionId;
      final res = a.processInput(
        _serverResponse(StunMessageType.allocateErrorResponse, firstTx,
            [const ErrorCodeAttr(code: StunErrorCode.unauthorized, reason: 'Unauthorized')]),
        remoteIp: _serverIp,
        remotePort: _serverPort,
      );
      expect(res.isErr, isTrue);
      expect(res.error, isA<ParseError>());
    });

    test('438 Stale Nonce on Refresh retries with the rotated nonce', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      final refreshTx =
          _stun(a.handleTimeout(TurnRefreshToken()).value.outputPackets.single)
              .transactionId;
      final after = a
          .processInput(
            _serverResponse(StunMessageType.refreshErrorResponse, refreshTx, [
              const ErrorCodeAttr(code: StunErrorCode.staleNonce, reason: 'Stale Nonce'),
              const RealmAttr('example.org'),
              NonceAttr(Uint8List.fromList('n3'.codeUnits)),
            ]),
            remoteIp: _serverIp,
            remotePort: _serverPort,
          )
          .value;
      expect(_stun(after.outputPackets.single).attribute<NonceAttr>()?.nonce,
          Uint8List.fromList('n3'.codeUnits));
    });

    test('438 Stale Nonce on CreatePermission retries with the rotated '
        'nonce', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      final permTx =
          _stun(a.createPermission(_peerIp).value.outputPackets.single)
              .transactionId;
      final after = a
          .processInput(
            _serverResponse(
                StunMessageType.createPermissionErrorResponse, permTx, [
              const ErrorCodeAttr(code: StunErrorCode.staleNonce, reason: 'Stale Nonce'),
              const RealmAttr('example.org'),
              NonceAttr(Uint8List.fromList('n4'.codeUnits)),
            ]),
            remoteIp: _serverIp,
            remotePort: _serverPort,
          )
          .value;
      expect(_stun(after.outputPackets.single).attribute<NonceAttr>()?.nonce,
          Uint8List.fromList('n4'.codeUnits));
    });

    test('DataIndication missing PEER or DATA is a ParseError', () {
      final a = _newAlloc();
      _runAuthFlow(a);
      final pkt = _serverResponse(
        StunMessageType.dataIndication,
        Csprng.randomTransactionId(),
        [XorPeerAddress(address: _peerIp, port: _peerPort)],
      );
      final res = a.processInput(pkt,
          remoteIp: _serverIp, remotePort: _serverPort);
      expect(res.isErr, isTrue);
      expect(res.error, isA<ParseError>());
    });
  });
}

/// Drive start() + 401 challenge response. Returns the transaction ID of
/// the authenticated Allocate retry that the state machine just sent.
Uint8List _runAuthRetry(TurnAllocation a) {
  final firstTx = _stun(a.start().value.outputPackets.single).transactionId;
  final retryRes = a
      .processInput(
        _serverResponse(StunMessageType.allocateErrorResponse, firstTx, [
          const ErrorCodeAttr(code: StunErrorCode.unauthorized, reason: 'Unauthorized'),
          const RealmAttr('example.org'),
          NonceAttr(Uint8List.fromList('n1'.codeUnits)),
        ]),
        remoteIp: _serverIp,
        remotePort: _serverPort,
      )
      .value;
  return _stun(retryRes.outputPackets.single).transactionId;
}

/// Drive the state machine through the full auth flow up to allocated.
void _runAuthFlow(TurnAllocation a) {
  final retryTx = _runAuthRetry(a);
  a.processInput(
    _serverAuthResponse(
      StunMessageType.allocateSuccessResponse,
      retryTx,
      [
        XorRelayedAddress(address: _relayedIp, port: _relayedPort),
        const LifetimeAttr(turnDefaultLifetimeSeconds),
      ],
      username: a.username,
      realm: 'example.org',
      password: a.password,
    ),
    remoteIp: _serverIp,
    remotePort: _serverPort,
  );
}
