/// webdartc offerer helper process for E2E tests.
///
/// Connects to the signaling server as offerer, creates a data channel,
/// sends 1 KB text + 64 KB binary, waits for echoes, then exits 0.
///
/// Usage:
///   dart run test/e2e/webdartc_offerer_helper.dart --port=PORT
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:webdartc/webdartc.dart';

// ── Minimal WebSocket client (stdlib only) ────────────────────────────────────

final class _WsClient {
  final Socket _socket;
  final _buf = <int>[];
  // ignore: close_sinks — closed in close()
  final _messages = StreamController<String>.broadcast();

  _WsClient._(this._socket);

  /// Connect to signaling server and perform HTTP→WebSocket upgrade.
  ///
  /// Uses a single socket subscription that switches from HTTP mode to
  /// WebSocket frame mode after the handshake (dart:io Socket is
  /// single-subscriber and cannot be re-listened after cancel).
  static Future<_WsClient> connect(int port) async {
    final socket = await Socket.connect('127.0.0.1', port);
    final client = _WsClient._(socket);

    // Build random 16-byte key.
    final keyBytes = Csprng.randomBytes(16);
    final key = base64.encode(keyBytes);

    // Send HTTP Upgrade request.
    socket.add(utf8.encode(
      'GET / HTTP/1.1\r\n'
      'Host: 127.0.0.1:$port\r\n'
      'Upgrade: websocket\r\n'
      'Connection: Upgrade\r\n'
      'Sec-WebSocket-Key: $key\r\n'
      'Sec-WebSocket-Version: 13\r\n'
      '\r\n',
    ));

    // Single subscription handles both HTTP handshake and WS frames.
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

  /// Returns null if no complete frame, '' for non-text frames, text otherwise.
  String? _tryParseFrame() {
    if (_buf.length < 2) return null;
    final opcode = _buf[0] & 0x0F;
    final b1 = _buf[1];
    final masked = (b1 & 0x80) != 0;
    final lenByte = b1 & 0x7F;

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

    if (opcode != 1) return ''; // non-text frame consumed

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
  int timeoutSec = 30;
  for (final arg in args) {
    if (arg.startsWith('--port=')) {
      port = int.parse(arg.substring('--port='.length));
    } else if (arg.startsWith('--timeout=')) {
      timeoutSec = int.parse(arg.substring('--timeout='.length));
    }
  }

  final exitCode = await _run(port, timeoutSec: timeoutSec);
  exit(exitCode);
}

Future<int> _run(int sigPort, {int timeoutSec = 30}) async {
  final ws = await _WsClient.connect(sigPort);
  ws.sendJson({'type': 'register', 'role': 'offerer'});

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
  pc.onIceConnectionStateChange.listen((state) {
    stderr.writeln('[offerer] ICE state: $state');
  });
  final dc = pc.createDataChannel('test');

  var textEchoed   = false;
  var binaryEchoed = false;
  final done = Completer<int>();

  // ICE candidates → relay.
  pc.onIceCandidate.listen((evt) {
    stderr.writeln('[offerer] local ICE candidate: ${evt.candidate}');
    ws.sendJson({
      'type': 'candidate',
      'candidate': {
        'candidate': evt.candidate,
        'sdpMid': evt.sdpMid,
        'sdpMLineIndex': evt.sdpMLineIndex,
      },
    });
  });

  // Expected payloads for echo verification
  final sentText = 'A' * 1024;
  final sentBin = Uint8List(64 * 1024);
  for (var i = 0; i < sentBin.length; i++) { sentBin[i] = i & 0xFF; }

  dc.onOpen.listen((_) async {
    stdout.writeln('[offerer] DataChannel open — sending messages');
    dc.send(sentText);
    dc.sendBinary(sentBin);
  });

  dc.onMessage.listen((evt) {
    if (!evt.isBinary) {
      final text = evt.text;
      if (text == sentText) {
        stdout.writeln('[offerer] text echo OK (${text.length} bytes)');
        textEchoed = true;
      } else {
        stderr.writeln('[offerer] text echo MISMATCH: '
            'sent=${sentText.length}b recv=${text.length}b '
            'match=${text == sentText}');
        if (!done.isCompleted) done.complete(1);
        return;
      }
    } else {
      final data = evt.data;
      var match = data.length == sentBin.length;
      if (match) {
        for (var i = 0; i < data.length; i++) {
          if (data[i] != sentBin[i]) { match = false; break; }
        }
      }
      if (match) {
        stdout.writeln('[offerer] binary echo OK (${data.length} bytes)');
        binaryEchoed = true;
      } else {
        stderr.writeln('[offerer] binary echo MISMATCH: '
            'sent=${sentBin.length}b recv=${data.length}b');
        if (!done.isCompleted) done.complete(1);
        return;
      }
    }
    if (textEchoed && binaryEchoed && !done.isCompleted) {
      stdout.writeln('[offerer] PASS');
      done.complete(0);
    }
  });

  // Create offer and send.
  final offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  stderr.writeln('[offerer] offer SDP:\n${offer.sdp}');
  ws.sendJson({'type': 'offer', 'sdp': offer.sdp});

  // Process signaling messages. onDone fires when the signaling
  // server's WebSocket is closed by its end (e.g. test tearDown
  // shutting the server down) — at that point there's no further
  // useful work for the offerer, so exit cleanly instead of squatting
  // on the runner until our own --timeout fires. Required for the
  // packet-loss e2e tests where the test body verifies its own state
  // and unawaits this subprocess; without this the leftover offerer
  // CPU starves later tests' subprocess startup.
  ws.messages.listen(
    (raw) async {
      final msg = jsonDecode(raw) as Map<String, dynamic>;
      stderr.writeln('[offerer] got signal: ${msg['type']}');
      switch (msg['type'] as String?) {
        case 'answer':
          stderr.writeln('[offerer] setRemoteDescription (answer SDP):\n${msg['sdp']}\n---');
          await pc.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.answer,
            sdp: msg['sdp'] as String,
          ));

        case 'candidate':
          final cand = msg['candidate'];
          if (cand != null && cand is Map<String, dynamic>) {
            stderr.writeln('[offerer] addIceCandidate: ${cand['candidate']}');
            await pc.addIceCandidate(IceCandidateInit(
              candidate: cand['candidate'] as String? ?? '',
              sdpMid: cand['sdpMid'] as String? ?? '0',
              sdpMLineIndex: cand['sdpMLineIndex'] as int? ?? 0,
            ));
          }
      }
    },
    onDone: () {
      if (!done.isCompleted) {
        stderr.writeln('[offerer] signaling WebSocket closed; exiting');
        done.complete(0);
      }
    },
  );

  final result = await done.future.timeout(
    Duration(seconds: timeoutSec),
    onTimeout: () {
      stderr.writeln('[offerer] TIMEOUT');
      return 1;
    },
  );

  await pc.close();
  await ws.close();
  return result;
}
