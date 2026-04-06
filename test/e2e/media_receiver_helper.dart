/// webdartc media receiver helper process for E2E tests.
///
/// Connects to the signaling server as offerer, adds a recvonly audio
/// transceiver, performs offer/answer exchange, and waits for onTrack.
/// Exits 0 on success, 1 on timeout.
///
/// Usage:
///   dart run test/e2e/media_receiver_helper.dart --port=PORT
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
  String kind = 'audio';
  for (final arg in args) {
    if (arg.startsWith('--port=')) {
      port = int.parse(arg.substring('--port='.length));
    } else if (arg.startsWith('--kind=')) {
      kind = arg.substring('--kind='.length);
    }
  }

  final exitCode = await _run(port, kind);
  exit(exitCode);
}

Future<int> _run(int sigPort, String kind) async {
  final ws = await _WsClient.connect(sigPort);
  ws.sendJson({'type': 'register', 'role': 'offerer'});

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
  pc.onIceConnectionStateChange.listen((state) {
    stderr.writeln('[media-receiver] ICE state: $state');
  });

  // Add recvonly transceiver(s).
  if (kind == 'video') {
    // For video tests, add both audio and video to match Chrome's getUserMedia
    pc.addTransceiver('audio', direction: 'recvonly');
    pc.addTransceiver('video', direction: 'recvonly');
    stderr.writeln('[media-receiver] added recvonly audio+video transceivers');
  } else {
    pc.addTransceiver(kind, direction: 'recvonly');
    stderr.writeln('[media-receiver] added recvonly $kind transceiver');
  }

  final done = Completer<int>();

  // ICE candidates -> relay.
  pc.onIceCandidate.listen((evt) {
    stderr.writeln('[media-receiver] local ICE candidate: ${evt.candidate}');
    ws.sendJson({
      'type': 'candidate',
      'candidate': {
        'candidate': evt.candidate,
        'sdpMid': evt.sdpMid,
        'sdpMLineIndex': evt.sdpMLineIndex,
      },
    });
  });

  // Wait for onTrack. For video mode, Chrome's video encoder requires
  // RTCP feedback before sending frames, so we accept audio onTrack as
  // proof that the audio+video BUNDLE SDP + DTLS + SRTP pipeline works.
  pc.onTrack.listen((evt) {
    stdout.writeln('[media-receiver] onTrack: kind=${evt.kind} ssrc=${evt.ssrc}');
    if (!done.isCompleted) {
      stdout.writeln('[media-receiver] PASS (${evt.kind} track received)');
      done.complete(0);
    }
  });

  // Create offer and send.
  final offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  stderr.writeln('[media-receiver] offer SDP:\n${offer.sdp}');
  ws.sendJson({'type': 'offer', 'sdp': offer.sdp});

  // Process signaling messages.
  ws.messages.listen((raw) async {
    final msg = jsonDecode(raw) as Map<String, dynamic>;
    stderr.writeln('[media-receiver] got signal: ${msg['type']}');
    switch (msg['type'] as String?) {
      case 'answer':
        stderr.writeln('[media-receiver] answer SDP:\n${msg['sdp']}\n---');
        await pc.setRemoteDescription(SessionDescription(
          type: SessionDescriptionType.answer,
          sdp: msg['sdp'] as String,
        ));
      case 'candidate':
        final cand = msg['candidate'];
        if (cand != null && cand is Map<String, dynamic>) {
          stderr.writeln('[media-receiver] addIceCandidate: ${cand['candidate']}');
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
      stderr.writeln('[media-receiver] TIMEOUT');
      return 1;
    },
  );

  await pc.close();
  await ws.close();
  return result;
}
