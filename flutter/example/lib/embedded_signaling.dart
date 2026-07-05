/// In-app Ayame-compatible signaling relay.
///
/// Port of `dart/example/signaling/server.dart` so that `flutter run`
/// alone is enough for a browser ↔ Flutter call: the app binds
/// HTTP + WebSocket on [port], relays `offer` / `answer` / `candidate`
/// between the two clients of a room, and serves the browser peer page
/// (`assets/browser_peer.html`) on `/`.
///
/// No `signalingKey` validation — local development relay only.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart' show rootBundle;

class EmbeddedSignalingServer {
  EmbeddedSignalingServer._(this._server, this.port);

  final HttpServer _server;
  final int port;

  static const _pingInterval = Duration(seconds: 30);

  final _rooms = <String, List<_Client>>{};
  Timer? _pingTimer;
  String? _html;

  /// 8080 first (the form's default URL), then fallbacks for when an
  /// unrelated dev server holds it.
  static const _candidatePorts = [8080, 8081, 8082, 8083];

  /// Binds `0.0.0.0` on the first free port of [_candidatePorts] and
  /// starts serving. Returns `null` when every port is taken — e.g.
  /// `dart/example/signaling/server.dart` or another instance of this
  /// app is running on all of them; join that one instead.
  static Future<EmbeddedSignalingServer?> start() async {
    for (final port in _candidatePorts) {
      // Probe loopback first: `anyIPv4` can bind even while another
      // process holds `127.0.0.1:port` (wildcard and specific address
      // coexist under SO_REUSEADDR) — that process, not us, would then
      // receive the browser's loopback connections.
      try {
        final probe =
            await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
        await probe.close();
      } on SocketException {
        continue;
      }
      final HttpServer server;
      try {
        server = await HttpServer.bind(InternetAddress.anyIPv4, port);
      } on SocketException {
        continue;
      }
      final self = EmbeddedSignalingServer._(server, port);
      self._pingTimer =
          Timer.periodic(_pingInterval, (_) => self._pingAll());
      unawaited(self._serve());
      return self;
    }
    return null;
  }

  /// `http://` URLs a browser can use to reach this server: loopback
  /// first, then every non-loopback IPv4 of this machine (for a browser
  /// on another device, e.g. desktop browser ↔ Android phone).
  Future<List<String>> urls() async {
    final out = ['http://127.0.0.1:$port/'];
    try {
      final ifaces = await NetworkInterface.list(
          type: InternetAddressType.IPv4, includeLoopback: false);
      for (final iface in ifaces) {
        for (final addr in iface.addresses) {
          out.add('http://${addr.address}:$port/');
        }
      }
    } on SocketException {
      // Interface enumeration can be denied (sandbox); loopback is enough.
    }
    return out;
  }

  Future<void> close() async {
    _pingTimer?.cancel();
    await _server.close(force: true);
  }

  Future<void> _serve() async {
    await for (final req in _server) {
      if (WebSocketTransformer.isUpgradeRequest(req)) {
        final ws = await WebSocketTransformer.upgrade(req);
        _handleWs(ws);
      } else {
        await _serveHtml(req);
      }
    }
  }

  Future<void> _serveHtml(HttpRequest req) async {
    _html ??= await rootBundle.loadString('assets/browser_peer.html');
    req.response
      ..headers.contentType = ContentType.html
      ..write(_html);
    await req.response.close();
  }

  void _handleWs(WebSocket ws) {
    final client = _Client(ws);
    stdout.writeln('[signaling] ws connected');
    ws.listen(
      (Object? data) => _onMessage(client, data),
      onDone: () => _onDisconnect(client),
      onError: (Object _) => _onDisconnect(client),
    );
  }

  void _onMessage(_Client client, Object? data) {
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
        // Keepalive ack — no action needed.
        return;
      case 'bye':
        _onDisconnect(client);
    }
  }

  void _handleRegister(_Client client, Map<String, dynamic> msg) {
    final roomId = msg['roomId'] as String?;
    final clientId = msg['clientId'] as String?;
    if (roomId == null || roomId.isEmpty) {
      client.ws
          .add(jsonEncode({'type': 'reject', 'reason': 'missing-room-id'}));
      return;
    }
    if (client.roomId != null) {
      client.ws
          .add(jsonEncode({'type': 'reject', 'reason': 'already-registered'}));
      return;
    }
    final room = _rooms.putIfAbsent(roomId, () => []);
    if (room.length >= 2) {
      client.ws
          .add(jsonEncode({'type': 'reject', 'reason': 'too-many-clients'}));
      return;
    }
    final isExistClient = room.isNotEmpty;
    client.roomId = roomId;
    client.clientId = clientId;
    room.add(client);
    stdout.writeln(
        '[signaling] room=$roomId client=$clientId joined (existing=$isExistClient)');
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
    if (roomId == null) return;
    stdout.writeln(
        '[signaling] ws disconnected (room=$roomId client=${client.clientId})');
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
}

class _Client {
  _Client(this.ws);
  final WebSocket ws;
  String? roomId;
  String? clientId;
}
