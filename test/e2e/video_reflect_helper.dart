/// webdartc video reflect helper for E2E tests.
///
/// Connects as answerer, receives Chrome's video, reflects RTP back.
///
/// Usage:
///   dart run test/e2e/video_reflect_helper.dart --port=PORT
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:webdartc/webdartc.dart';

// ── Minimal WebSocket client ────────────────────────────────────────────────

final class _WsClient {
  final Socket _socket;
  final _buf = <int>[];
  final _messages = StreamController<String>.broadcast();
  _WsClient._(this._socket);

  static Future<_WsClient> connect(int port) async {
    final socket = await Socket.connect('127.0.0.1', port);
    final client = _WsClient._(socket);
    final key = base64.encode(Csprng.randomBytes(16));
    socket.add(utf8.encode(
      'GET / HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nUpgrade: websocket\r\n'
      'Connection: Upgrade\r\nSec-WebSocket-Key: $key\r\n'
      'Sec-WebSocket-Version: 13\r\n\r\n',
    ));
    final completer = Completer<_WsClient>();
    final httpBuf = StringBuffer();
    bool done = false;
    socket.listen((data) {
      if (!done) {
        httpBuf.write(utf8.decode(data, allowMalformed: true));
        if (httpBuf.toString().contains('\r\n\r\n')) {
          done = true;
          if (!completer.isCompleted) completer.complete(client);
        }
      } else {
        client._buf.addAll(data);
        client._drainFrames();
      }
    }, onError: (_) { client._messages.close(); if (!completer.isCompleted) completer.completeError('err'); },
       onDone: () { client._messages.close(); if (!completer.isCompleted) completer.complete(client); });
    return completer.future;
  }

  void _drainFrames() { while (true) { final m = _tryParse(); if (m == null) break; if (m.isNotEmpty) _messages.add(m); } }
  String? _tryParse() {
    if (_buf.length < 2) return null;
    final masked = (_buf[1] & 0x80) != 0;
    final lenByte = _buf[1] & 0x7F;
    final opcode = _buf[0] & 0x0F;
    int hLen = 2 + (masked ? 4 : 0); int pLen;
    if (lenByte < 126) { pLen = lenByte; }
    else if (lenByte == 126) { if (_buf.length < 4) return null; pLen = (_buf[2] << 8) | _buf[3]; hLen += 2; }
    else { if (_buf.length < 10) return null; pLen = 0; for (var i = 0; i < 8; i++) pLen = (pLen << 8) | _buf[2+i]; hLen += 8; }
    if (_buf.length < hLen + pLen) return null;
    final mk = masked ? _buf.sublist(hLen - 4, hLen) : null;
    final raw = _buf.sublist(hLen, hLen + pLen);
    _buf.removeRange(0, hLen + pLen);
    if (opcode != 1) return '';
    final p = masked ? List<int>.generate(raw.length, (i) => raw[i] ^ mk![i % 4]) : raw;
    return utf8.decode(p, allowMalformed: true);
  }

  void sendJson(Map<String, dynamic> msg) {
    final payload = utf8.encode(jsonEncode(msg));
    final len = payload.length;
    final mk = Csprng.randomBytes(4);
    late List<int> h;
    if (len < 126) { h = [0x81, 0x80 | len]; }
    else if (len < 65536) { h = [0x81, 0xFE, (len >> 8) & 0xFF, len & 0xFF]; }
    else { h = [0x81, 0xFF]; for (var i = 7; i >= 0; i--) h.add((len >> (i*8)) & 0xFF); }
    h.addAll(mk);
    final m = List<int>.generate(len, (i) => payload[i] ^ mk[i % 4]);
    _socket.add(Uint8List.fromList([...h, ...m]));
  }

  Stream<String> get messages => _messages.stream;
  Future<void> close() async => _socket.destroy();
}

// ── Main ──────────────────────────────────────────────────────────────────────

void main(List<String> args) async {
  int port = 8080;
  for (final arg in args) {
    if (arg.startsWith('--port=')) port = int.parse(arg.substring(7));
  }
  exit(await _run(port));
}

Future<int> _run(int sigPort) async {
  final ws = await _WsClient.connect(sigPort);
  ws.sendJson({'type': 'register', 'role': 'answerer'});

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
  pc.onIceConnectionStateChange.listen((s) => stderr.writeln('[reflect] ICE: $s'));

  RtpSender? videoSender;
  int reflected = 0;
  final done = Completer<int>();

  pc.onIceCandidate.listen((evt) {
    ws.sendJson({'type': 'candidate', 'candidate': {
      'candidate': evt.candidate, 'sdpMid': evt.sdpMid, 'sdpMLineIndex': evt.sdpMLineIndex,
    }});
  });

  // Reflect received video RTP back, count video packets
  pc.onTrack.listen((evt) {
    stderr.writeln('[reflect] onTrack: ${evt.kind} ssrc=${evt.ssrc}');
    if (evt.kind == 'video' && videoSender != null) {
      evt.receiver.onRtp.listen((rtp) {
        videoSender!.sendRtp(rtp.payload, marker: rtp.marker, timestamp: rtp.timestamp);
        reflected++;
        if (reflected == 50 && !done.isCompleted) {
          stdout.writeln('[reflect] PASS (reflected $reflected video packets)');
          done.complete(0);
        }
      });
    }
  });

  ws.messages.listen((raw) async {
    final msg = jsonDecode(raw) as Map<String, dynamic>;
    stderr.writeln('[reflect] signal: ${msg['type']}');
    switch (msg['type'] as String?) {
      case 'offer':
        // Add audio (recvonly) + video (sendrecv) transceivers
        pc.addTransceiver('audio', direction: 'recvonly');
        pc.addTransceiver('video', direction: 'sendrecv');
        videoSender = pc.getSenders().where((s) => s.kind == 'video').firstOrNull;

        await pc.setRemoteDescription(SessionDescription(
          type: SessionDescriptionType.offer, sdp: msg['sdp'] as String));
        final answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        stderr.writeln('[reflect] answer SDP:\n${answer.sdp}');
        ws.sendJson({'type': 'answer', 'sdp': answer.sdp});

      case 'candidate':
        final c = msg['candidate'];
        if (c != null && c is Map<String, dynamic>) {
          await pc.addIceCandidate(IceCandidateInit(
            candidate: (c['candidate'] as String?) ?? '',
            sdpMid: (c['sdpMid'] as String?) ?? '0',
            sdpMLineIndex: (c['sdpMLineIndex'] as int?) ?? 0,
          ));
        }
    }
  });

  final result = await done.future.timeout(
    const Duration(seconds: 30),
    onTimeout: () { stderr.writeln('[reflect] TIMEOUT (reflected=$reflected)'); return 1; },
  );
  await pc.close();
  await ws.close();
  return result;
}
