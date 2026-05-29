/// HTTP + WebSocket Ayame-compatible signaling relay.
///
/// Implements a minimal subset of the OpenAyame signaling protocol
/// (https://github.com/OpenAyame/ayame-spec): two clients register with
/// the same `roomId`, the server forwards `offer` / `answer` /
/// `candidate` messages between them, and pings keep the WS alive. No
/// `signalingKey` validation — local development relay.
///
/// Also serves the browser client HTML on `/`.
///
/// Usage:
///   dart run example/signaling/server.dart [--port=8080]
///
/// Pair endpoints with the same Ayame URL: `ws://127.0.0.1:8080/signaling`.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../serve.dart';

const _pingInterval = Duration(seconds: 30);

class _Client {
  _Client(this.ws);
  final WebSocket ws;
  String? roomId;
  String? clientId;
}

final _rooms = <String, List<_Client>>{};

Future<void> main(List<String> args) async {
  var port = 8080;
  for (final a in args) {
    if (a.startsWith('--port=')) port = int.parse(a.substring(7));
  }

  final server = await HttpServer.bind(InternetAddress.anyIPv4, port);
  print('signaling (Ayame) listening on http://127.0.0.1:$port');

  Timer.periodic(_pingInterval, (_) => _pingAll());

  await for (final req in server) {
    if (WebSocketTransformer.isUpgradeRequest(req)) {
      final ws = await WebSocketTransformer.upgrade(req);
      _handleWs(ws);
    } else {
      await serveExampleStatic(req);
    }
  }
}

void _handleWs(WebSocket ws) {
  final client = _Client(ws);
  print('[ws] connected');
  ws.listen(
    (data) => _onMessage(client, data),
    onDone: () => _onDisconnect(client),
    onError: (_) => _onDisconnect(client),
  );
}

void _onMessage(_Client client, dynamic data) {
  if (data is! String) return;
  final Map<String, dynamic> msg;
  try {
    msg = jsonDecode(data) as Map<String, dynamic>;
  } on FormatException {
    return;
  }
  switch (msg['type'] as String?) {
    case 'register':
      _handleRegister(client, msg);
    case 'offer':
    case 'answer':
    case 'candidate':
      _forwardToPeer(client, data);
    case 'pong':
      // Keepalive ack — no action needed; clients just need to send something.
      return;
    case 'bye':
      _onDisconnect(client);
  }
}

void _handleRegister(_Client client, Map<String, dynamic> msg) {
  final roomId = msg['roomId'] as String?;
  final clientId = msg['clientId'] as String?;
  if (roomId == null || roomId.isEmpty) {
    client.ws.add(jsonEncode({'type': 'reject', 'reason': 'missing-room-id'}));
    return;
  }
  if (client.roomId != null) {
    client.ws.add(jsonEncode({'type': 'reject', 'reason': 'already-registered'}));
    return;
  }
  final room = _rooms.putIfAbsent(roomId, () => []);
  if (room.length >= 2) {
    client.ws.add(jsonEncode({'type': 'reject', 'reason': 'too-many-clients'}));
    return;
  }
  final isExistClient = room.isNotEmpty;
  client.roomId = roomId;
  client.clientId = clientId;
  room.add(client);
  print('[room=$roomId] client=$clientId joined (existing=$isExistClient)');
  client.ws.add(jsonEncode({
    'type': 'accept',
    'isExistClient': isExistClient,
    'iceServers': <Map<String, dynamic>>[],
  }));
}

void _forwardToPeer(_Client from, String raw) {
  final roomId = from.roomId;
  if (roomId == null) return;
  final room = _rooms[roomId];
  if (room == null) return;
  for (final c in room) {
    if (!identical(c, from)) c.ws.add(raw);
  }
}

void _onDisconnect(_Client client) {
  final roomId = client.roomId;
  print('[ws] disconnected (room=$roomId client=${client.clientId})');
  if (roomId == null) return;
  final room = _rooms[roomId];
  if (room == null) return;
  room.remove(client);
  client.roomId = null;
  if (room.isEmpty) {
    _rooms.remove(roomId);
  } else {
    final bye = jsonEncode({'type': 'bye'});
    for (final other in room) {
      other.ws.add(bye);
    }
  }
}

void _pingAll() {
  final ping = jsonEncode({'type': 'ping'});
  for (final room in _rooms.values) {
    for (final c in room) {
      c.ws.add(ping);
    }
  }
}

