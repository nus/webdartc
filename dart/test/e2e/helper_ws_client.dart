/// Shared signaling WebSocket client for the E2E helper processes.
///
/// Wraps `dart:io`'s spec-compliant [WebSocket] (the signaling server is a
/// `dart:io` `WebSocketTransformer`, so both ends speak full RFC 6455 —
/// fragmentation, ping/pong, and handshake framing are handled by the SDK).
///
/// This replaces the per-helper hand-rolled WebSocket clients, whose frame
/// parser dropped any bytes that arrived in the same TCP segment as the
/// HTTP 101 upgrade response. When the server relayed the browser's offer
/// immediately after the upgrade (common on CI where the offer is queued
/// before the helper connects), the parser lost frame alignment and either
/// crashed decoding mid-SDP garbage as JSON or silently lost the offer and
/// timed out.
library;

import 'dart:convert';
import 'dart:io';

final class HelperWsClient {
  final WebSocket _ws;

  HelperWsClient._(this._ws);

  static Future<HelperWsClient> connect(int port) async =>
      HelperWsClient._(await WebSocket.connect('ws://127.0.0.1:$port'));

  void sendJson(Map<String, dynamic> msg) => _ws.add(jsonEncode(msg));

  /// Text messages from the server. Single-subscription: the underlying
  /// [WebSocket] buffers anything that arrives before the helper's `.listen`,
  /// so an early offer/candidate is never lost.
  Stream<String> get messages =>
      _ws.where((Object? data) => data is String).cast<String>();

  Future<void> close() => _ws.close();
}
