/// Video reflect helper using RTP Transport API (replacePacketReceiver/Sender).
///
/// Same as video_reflect_helper.dart but uses the W3C RTP Transport API path
/// that server.dart and ayame_client.dart use, to verify that code path works.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:webdartc/webdartc.dart';

// ── Minimal WebSocket client (same as video_reflect_helper.dart) ────────────

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

// ── VP8 keyframe detection (RFC 7741) ───────────────────────────────────────

bool _isVp8Keyframe(Uint8List payload) {
  if (payload.isEmpty) return false;
  final b0 = payload[0];
  final s = (b0 >> 4) & 1;
  final partId = b0 & 0x0F;
  if (s != 1 || partId != 0) return false;
  var off = 1;
  if ((b0 >> 7) & 1 == 1) {
    if (off >= payload.length) return false;
    final ext = payload[off++];
    if ((ext >> 7) & 1 == 1) {
      if (off >= payload.length) return false;
      off += (payload[off] & 0x80 != 0) ? 2 : 1;
    }
    if ((ext >> 6) & 1 == 1) off++;
    if ((ext >> 5) & 1 == 1) off++;
  }
  if (off >= payload.length) return false;
  return (payload[off] & 0x01) == 0;
}

// ── Main ────────────────────────────────────────────────────────────────────

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

  int reflected = 0;

  pc.onIceCandidate.listen((evt) {
    ws.sendJson({'type': 'candidate', 'candidate': {
      'candidate': evt.candidate, 'sdpMid': evt.sdpMid, 'sdpMLineIndex': evt.sdpMLineIndex,
    }});
  });

  // Use server.dart-style reflect: replacePacketReceiver + replacePacketSender
  pc.onTrack.listen((evt) async {
    stderr.writeln('[reflect] onTrack: ${evt.kind} ssrc=${evt.ssrc}');

    // Get matching sender (same pattern as server.dart)
    final senders = pc.getSenders();
    final sender = senders.where((s) => s.kind == evt.kind).firstOrNull;
    if (sender == null) {
      stderr.writeln('[reflect] WARNING: no sender for kind=${evt.kind}');
      return;
    }
    stderr.writeln('[reflect] reflecting ${evt.kind} -> sender ssrc=${sender.ssrc}');

    // W3C RTP Transport API path (same as server.dart)
    final packetReceiver = await evt.receiver.replacePacketReceiver();
    final packetSender = await sender.replacePacketSender();

    packetReceiver.onReceivedRtp.listen((_) {
      final packets = packetReceiver.readReceivedRtp(100);
      for (final rtp in packets) {
        if (rtp.payload.isEmpty) continue;
        packetSender.sendRtp(rtp);
        if (evt.kind == 'video') {
          reflected++;
          if (reflected <= 3 || reflected % 100 == 0) {
            stderr.writeln('[reflect] video #$reflected seq=${rtp.sequenceNumber}');
          }
        }
      }
    });
  });

  ws.messages.listen((raw) async {
    final msg = jsonDecode(raw) as Map<String, dynamic>;
    stderr.writeln('[reflect] signal: ${msg['type']}');
    switch (msg['type'] as String?) {
      case 'offer':
        stderr.writeln('[reflect] offer SDP:\n${msg['sdp']}');
        pc.addTransceiver('audio', direction: 'sendrecv');
        pc.addTransceiver('video', direction: 'sendrecv');

        await pc.setRemoteDescription(SessionDescription(
          type: SessionDescriptionType.offer, sdp: msg['sdp'] as String));
        final answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        // Inject short keyframe interval so Chrome sends periodic keyframes.
        // PLI via SRTCP may not reach Chrome, so we need encoder-level periodicity.
        var sdp = answer.sdp;
        sdp = sdp.replaceAllMapped(RegExp(r'(a=rtpmap:96 VP8/90000)'),
            (m) => '${m[1]}\r\na=fmtp:96 x-google-max-keyframe-interval=30');
        stderr.writeln('[reflect] answer SDP:\n$sdp');
        ws.sendJson({'type': 'answer', 'sdp': sdp});

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

  // Keep reflecting until killed by the test runner (or 60s timeout).
  await Future<void>.delayed(const Duration(seconds: 60));
  stderr.writeln('[reflect] exiting (reflected=$reflected video packets)');
  await pc.close();
  await ws.close();
  return 0;
}
