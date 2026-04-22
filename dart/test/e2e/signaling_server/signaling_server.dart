/// Minimal WebSocket signaling server — dart:io WebSocket only.
///
/// Protocol:
///   Client A sends: { "type": "register", "role": "offerer" | "answerer" }
///   Client A sends: { "type": "offer" | "answer" | "candidate", ...payload... }
///   Server relays each message to the other registered client.
library;

import 'dart:convert';
import 'dart:io';

import '../udp_proxy/udp_proxy.dart';

/// A running signaling server.
final class SignalingServer {
  final HttpServer _server;
  final int port;
  final List<WebSocket> _clients = [];
  final UdpProxy? _proxy;
  bool _closed = false;

  // Track client registration order for proxy port assignment.
  // First registered client = A, second = B.
  WebSocket? _clientA;
  WebSocket? _clientB;

  SignalingServer._(this._server, this.port, this._proxy) {
    _server.listen(_onRequest);
  }

  /// Bind to a free OS-assigned port and start listening.
  /// Pass [proxy] to enable candidate rewriting for impairment testing.
  static Future<SignalingServer> start({UdpProxy? proxy}) async {
    final server =
        await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    return SignalingServer._(server, server.port, proxy);
  }

  Future<void> close() async {
    _closed = true;
    for (final ws in _clients) {
      await ws.close();
    }
    await _server.close();
  }

  void _onRequest(HttpRequest request) {
    if (_closed) {
      request.response
        ..statusCode = HttpStatus.forbidden
        ..close();
      return;
    }
    WebSocketTransformer.upgrade(request).then((ws) {
      _clients.add(ws);
      ws.listen(
        (data) {
          if (data is! String) return;
          try {
            final msg = jsonDecode(data) as Map<String, dynamic>;
            _relay(ws, msg);
          } catch (_) {}
        },
        onDone: () => _clients.remove(ws),
        onError: (_) => _clients.remove(ws),
      );
    }).catchError((_) {});
  }

  void _relay(WebSocket sender, Map<String, dynamic> msg) {
    // Track registration order for proxy assignment.
    if (msg['type'] == 'register') {
      if (_clientA == null) {
        _clientA = sender;
      } else if (_clientB == null && !identical(sender, _clientA)) {
        _clientB = sender;
      }
    }

    // Rewrite ICE candidates when proxy is active.
    if (_proxy != null) {
      msg = _rewriteForProxy(sender, msg);
    }

    final encoded = jsonEncode(msg);
    for (final ws in _clients) {
      if (!identical(ws, sender)) ws.add(encoded);
    }
  }

  // ── Proxy candidate rewriting ───────────────────────────────────────────────

  /// Rewrite ICE candidate addresses to route through the proxy.
  ///
  /// Client A's candidates → rewritten to proxy.port1 (Peer B sends to P1).
  /// Client B's candidates → rewritten to proxy.port2 (Peer A sends to P2).
  Map<String, dynamic> _rewriteForProxy(
      WebSocket sender, Map<String, dynamic> msg) {
    final proxy = _proxy!;
    final isA = identical(sender, _clientA);
    final isB = identical(sender, _clientB);
    if (!isA && !isB) return msg;

    // Proxy port that the OTHER peer will send to.
    final proxyPort = isA ? proxy.port1 : proxy.port2;

    final type = msg['type'];

    if (type == 'candidate') {
      final cand = msg['candidate'];
      if (cand is Map<String, dynamic>) {
        final candStr = cand['candidate'] as String?;
        if (candStr != null) {
          final (rewritten, origIp, origPort) =
              _rewriteCandidateString(candStr, proxyPort);
          if (origPort != null) {
            _setProxyRealAddress(proxy, isA, origIp, origPort);
          }
          msg = Map<String, dynamic>.from(msg);
          msg['candidate'] = Map<String, dynamic>.from(cand)
            ..['candidate'] = rewritten;
        }
      }
      return msg;
    }

    if (type == 'offer' || type == 'answer') {
      final sdp = msg['sdp'] as String?;
      if (sdp != null) {
        String? lastOrigIp;
        int? lastOrigPort;
        final rewritten = sdp.replaceAllMapped(
          RegExp(
              r'^(a=candidate:\S+ \d+ )(udp)( \d+ )([\d.]+) (\d+)( typ .*)$',
              multiLine: true, caseSensitive: false),
          (m) {
            lastOrigIp = m[4];
            lastOrigPort = int.tryParse(m[5]!);
            return '${m[1]}${m[2]}${m[3]}127.0.0.1 $proxyPort${m[6]}';
          },
        );
        if (lastOrigPort != null) {
          _setProxyRealAddress(proxy, isA, lastOrigIp, lastOrigPort!);
        }
        msg = Map<String, dynamic>.from(msg)..['sdp'] = rewritten;
      }
      return msg;
    }

    return msg;
  }

  /// Set the proxy's real forward address for a peer.
  void _setProxyRealAddress(
      UdpProxy proxy, bool isA, String? origIp, int origPort) {
    final addr = origIp != null
        ? InternetAddress(origIp)
        : InternetAddress.loopbackIPv4;
    if (isA) {
      proxy.setRealAddressA(addr, origPort);
    } else {
      proxy.setRealAddressB(addr, origPort);
    }
  }

  /// Rewrite a single UDP candidate string's IP and port.
  /// Returns (rewritten, originalIp, originalPort) or (original, null, null).
  /// Only rewrites UDP candidates — TCP candidates are left unchanged.
  static (String, String?, int?) _rewriteCandidateString(
      String candidate, int newPort) {
    final re = RegExp(
        r'^(candidate:\S+ \d+ )(udp)( \d+ )([\d.]+) (\d+)( typ .*)$',
        caseSensitive: false);
    final m = re.firstMatch(candidate);
    if (m == null) return (candidate, null, null);
    final origIp = m[4];
    final origPort = int.tryParse(m[5]!);
    return ('${m[1]}${m[2]}${m[3]}127.0.0.1 $newPort${m[6]}', origIp, origPort);
  }
}
