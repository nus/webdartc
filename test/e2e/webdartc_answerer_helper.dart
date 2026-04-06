/// webdartc answerer helper process for E2E tests.
///
/// Connects to the signaling server as answerer, waits for an offer from
/// Chrome (offerer), creates an answer, and waits for a data channel
/// message exchange.
///
/// Usage:
///   dart run test/e2e/webdartc_answerer_helper.dart --port=PORT
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:webdartc/webdartc.dart';

// ── Minimal WebSocket client (same as webdartc_offerer_helper.dart) ──────────

final class _WsClient {
  final Socket _socket;
  final _buf = <int>[];
  final _messages = StreamController<String>.broadcast();

  _WsClient._(this._socket);

  static Future<_WsClient> connect(int port) async {
    final socket = await Socket.connect('127.0.0.1', port);
    final client = _WsClient._(socket);

    final keyBytes = Csprng.randomBytes(16);
    final key = base64.encode(keyBytes);

    socket.add(utf8.encode(
      'GET / HTTP/1.1\r\n'
      'Host: 127.0.0.1:$port\r\n'
      'Upgrade: websocket\r\n'
      'Connection: Upgrade\r\n'
      'Sec-WebSocket-Key: $key\r\n'
      'Sec-WebSocket-Version: 13\r\n'
      '\r\n',
    ));

    final completer = Completer<_WsClient>();
    final httpBuf = StringBuffer();
    bool handshakeDone = false;

    socket.listen(
      (data) {
        if (!handshakeDone) {
          httpBuf.write(utf8.decode(data, allowMalformed: true));
          if (httpBuf.toString().contains('\r\n\r\n')) {
            handshakeDone = true;
            if (!completer.isCompleted) completer.complete(client);
          }
        } else {
          client._buf.addAll(data);
          client._drainFrames();
        }
      },
      onError: (Object e) {
        client._messages.close();
        if (!completer.isCompleted) completer.completeError(e);
      },
      onDone: () {
        client._messages.close();
        if (!completer.isCompleted) completer.complete(client);
      },
    );

    return completer.future;
  }

  void _drainFrames() {
    while (true) {
      final msg = _tryParseFrame();
      if (msg == null) break;
      if (msg.isNotEmpty) _messages.add(msg);
    }
  }

  String? _tryParseFrame() {
    if (_buf.length < 2) return null;
    final b1 = _buf[1];
    final masked = (b1 & 0x80) != 0;
    final lenByte = b1 & 0x7F;
    final opcode = _buf[0] & 0x0F;

    int headerLen = 2 + (masked ? 4 : 0);
    int payloadLen;

    if (lenByte < 126) {
      payloadLen = lenByte;
    } else if (lenByte == 126) {
      if (_buf.length < 4) return null;
      payloadLen = (_buf[2] << 8) | _buf[3];
      headerLen += 2;
    } else {
      if (_buf.length < 10) return null;
      payloadLen = 0;
      for (var i = 0; i < 8; i++) {
        payloadLen = (payloadLen << 8) | _buf[2 + i];
      }
      headerLen += 8;
    }

    if (_buf.length < headerLen + payloadLen) return null;

    final maskKey = masked ? _buf.sublist(headerLen - 4, headerLen) : null;
    final raw = _buf.sublist(headerLen, headerLen + payloadLen);
    _buf.removeRange(0, headerLen + payloadLen);

    if (opcode != 1) return '';

    final payload = masked
        ? List<int>.generate(raw.length, (i) => raw[i] ^ maskKey![i % 4])
        : raw;
    return utf8.decode(payload, allowMalformed: true);
  }

  void sendJson(Map<String, dynamic> msg) {
    final payload = utf8.encode(jsonEncode(msg));
    final len = payload.length;
    final maskKey = Csprng.randomBytes(4);

    late List<int> header;
    if (len < 126) {
      header = [0x81, 0x80 | len];
    } else if (len < 65536) {
      header = [0x81, 0xFE, (len >> 8) & 0xFF, len & 0xFF];
    } else {
      header = [0x81, 0xFF];
      for (var i = 7; i >= 0; i--) {
        header.add((len >> (i * 8)) & 0xFF);
      }
    }
    header.addAll(maskKey);

    final masked = List<int>.generate(
      payload.length,
      (i) => payload[i] ^ maskKey[i % 4],
    );
    _socket.add(Uint8List.fromList([...header, ...masked]));
  }

  Stream<String> get messages => _messages.stream;

  Future<void> close() async {
    _socket.destroy();
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

void main(List<String> args) async {
  int port = 8080;
  for (final arg in args) {
    if (arg.startsWith('--port=')) {
      port = int.parse(arg.substring('--port='.length));
    }
  }

  final exitCode = await _run(port);
  exit(exitCode);
}

Future<int> _run(int sigPort) async {
  final ws = await _WsClient.connect(sigPort);
  // Register as answerer — wait for Chrome's offer.
  ws.sendJson({'type': 'register', 'role': 'answerer'});

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
  pc.onIceConnectionStateChange.listen((state) {
    stderr.writeln('[answerer] ICE state: $state');
  });

  final done = Completer<int>();

  // ICE candidates → relay.
  pc.onIceCandidate.listen((evt) {
    stderr.writeln('[answerer] local ICE candidate: ${evt.candidate}');
    ws.sendJson({
      'type': 'candidate',
      'candidate': {
        'candidate': evt.candidate,
        'sdpMid': evt.sdpMid,
        'sdpMLineIndex': evt.sdpMLineIndex,
      },
    });
  });

  // Remote data channel from Chrome's offer.
  pc.onDataChannel.listen((evt) {
    final ch = evt.channel;
    stderr.writeln('[answerer] onDataChannel: label=${ch.label} id=${ch.id}');
    ch.onOpen.listen((_) {
      stdout.writeln('[answerer] DataChannel open: ${ch.label}');
      // Send a message to Chrome
      ch.send('hello from webdartc answerer');
    });
    ch.onMessage.listen((msg) {
      stdout.writeln('[answerer] received: ${msg.isBinary ? "binary" : "text"} ${msg.data.length}b');
      // Echo back
      if (msg.isBinary) {
        ch.sendBinary(msg.data);
      } else {
        ch.send(msg.text);
      }
      if (!done.isCompleted) {
        stdout.writeln('[answerer] PASS');
        done.complete(0);
      }
    });
  });

  // Process signaling messages.
  ws.messages.listen((raw) async {
    final msg = jsonDecode(raw) as Map<String, dynamic>;
    stderr.writeln('[answerer] got signal: ${msg['type']}');
    switch (msg['type'] as String?) {
      case 'offer':
        stderr.writeln('[answerer] setRemoteDescription (offer)');
        await pc.setRemoteDescription(SessionDescription(
          type: SessionDescriptionType.offer,
          sdp: msg['sdp'] as String,
        ));
        final answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        stderr.writeln('[answerer] answer SDP:\n${answer.sdp}');
        ws.sendJson({'type': 'answer', 'sdp': answer.sdp});

      case 'candidate':
        final cand = msg['candidate'];
        if (cand != null && cand is Map<String, dynamic>) {
          stderr.writeln('[answerer] addIceCandidate: ${cand['candidate']}');
          await pc.addIceCandidate(IceCandidateInit(
            candidate: cand['candidate'] as String? ?? '',
            sdpMid: cand['sdpMid'] as String? ?? '0',
            sdpMLineIndex: cand['sdpMLineIndex'] as int? ?? 0,
          ));
        }
    }
  });

  // Timeout after 30 s.
  final result = await done.future.timeout(
    const Duration(seconds: 30),
    onTimeout: () {
      stderr.writeln('[answerer] TIMEOUT');
      return 1;
    },
  );

  await pc.close();
  await ws.close();
  return result;
}
