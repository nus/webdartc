/// Self-contained Dart sender peer for the media sample.
///
/// HTTP + WS + Dart peer in one binary. Serves `web/index.html` on `/`,
/// accepts a WebSocket upgrade, waits for the browser to signal
/// `{type:'ready'}`, then offers `sendonly` (or `sendrecv` with `--bidir`)
/// video and pushes a FakeVideoSource stream encoded with VP8 or H.264.
///
/// Usage:
///   dart run example/media/bin/sender.dart \
///     [--port=8080] [--codec=vp8|h264] [--bidir]
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/rtp/packetizer.dart';
import 'package:webdartc/webdartc.dart';

int _port = 8080;
String _codec = 'vp8';
bool _bidir = false;

Future<void> main(List<String> args) async {
  for (final a in args) {
    if (a.startsWith('--port=')) _port = int.parse(a.substring(7));
    if (a.startsWith('--codec=')) _codec = a.substring(8).toLowerCase();
    if (a == '--bidir') _bidir = true;
  }
  if (_codec != 'vp8' && _codec != 'h264') {
    stderr.writeln('Unsupported codec: $_codec (expected vp8 or h264)');
    exit(2);
  }

  switch (_codec) {
    case 'vp8':
      registerVp8Codec();
    case 'h264':
      registerH264Codec();
  }

  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  stdout.writeln('[sender] listening on http://127.0.0.1:$_port '
      '(codec=$_codec, bidir=$_bidir)');
  stdout.writeln('[sender] open the URL in Chrome — append `?bidir=1` to also '
      'push a camera track back for the Dart decoder');

  await for (final req in server) {
    if (WebSocketTransformer.isUpgradeRequest(req)) {
      final ws = await WebSocketTransformer.upgrade(req);
      unawaited(_handleWs(ws));
    } else {
      await _serveStatic(req);
    }
  }
}

Future<void> _serveStatic(HttpRequest req) async {
  final path = req.uri.path == '/' ? '/index.html' : req.uri.path;
  final file = File('${_webRoot()}$path');
  if (!await file.exists()) {
    req.response.statusCode = HttpStatus.notFound;
    await req.response.close();
    return;
  }
  final ext = path.split('.').last;
  final contentType = switch (ext) {
    'html' => 'text/html; charset=utf-8',
    'js' => 'application/javascript; charset=utf-8',
    'css' => 'text/css; charset=utf-8',
    _ => 'application/octet-stream',
  };
  req.response.headers.contentType = ContentType.parse(contentType);
  await req.response.addStream(file.openRead());
  await req.response.close();
}

String _webRoot() {
  final script = Platform.script.toFilePath();
  final dir = Directory(script).parent.parent;
  return '${dir.path}/web';
}

Future<void> _handleWs(WebSocket ws) async {
  stdout.writeln('[sender] WS client connected');

  final pc = PeerConnection(configuration: const PeerConnectionConfiguration());
  pc.addTransceiver(
    'video',
    direction: _bidir ? 'sendrecv' : 'sendonly',
    preferredCodecs: [_codec.toUpperCase()],
  );
  final sender = pc.getSenders().firstWhere((s) => s.kind == 'video');

  VideoEncoder? encoder;
  StreamSubscription<VideoFrame>? frameSub;

  Future<void> teardown() async {
    await frameSub?.cancel();
    encoder?.close();
    await pc.close();
  }

  pc.onIceCandidate.listen((evt) {
    ws.add(jsonEncode({
      'type': 'candidate',
      'candidate': {
        'candidate': evt.candidate,
        'sdpMid': evt.sdpMid,
        'sdpMLineIndex': evt.sdpMLineIndex,
      }
    }));
  });

  pc.onIceConnectionStateChange
      .listen((s) => stdout.writeln('[sender] ICE: $s'));
  pc.onConnectionStateChange.listen((s) {
    stdout.writeln('[sender] PC: $s');
    if (s == PeerConnectionState.connected) {
      final stream = _startVideoStream(sender);
      encoder = stream.encoder;
      frameSub = stream.sub;
    }
  });

  if (_bidir) {
    pc.onTrack.listen((evt) {
      if (evt.kind != 'video') return;
      stdout.writeln('[sender] onTrack kind=${evt.kind} ssrc=${evt.ssrc} — '
          'starting depacketizer + decoder');
      _pipeIncoming(evt.receiver, _codec);
    });
  }

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type'] as String?) {
        // Browser sends `ready` after attaching its onmessage handler and
        // (if `?bidir=1`) finishing getUserMedia. Only then is it safe to
        // push the offer — otherwise the offer can race the browser's setup.
        case 'ready':
          stdout.writeln('[sender] browser ready — sending offer');
          final offer = await pc.createOffer();
          await pc.setLocalDescription(offer);
          ws.add(jsonEncode({'type': 'offer', 'sdp': offer.sdp}));
        case 'answer':
          await pc.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.answer,
            sdp: msg['sdp'] as String,
          ));
        case 'candidate':
          final c = msg['candidate'];
          if (c is Map<String, dynamic>) {
            await pc.addIceCandidate(IceCandidateInit(
              candidate: (c['candidate'] as String?) ?? '',
              sdpMid: (c['sdpMid'] as String?) ?? '0',
              sdpMLineIndex: (c['sdpMLineIndex'] as int?) ?? 0,
            ));
          }
      }
    },
    onDone: () async {
      stdout.writeln('[sender] WS client disconnected');
      await teardown();
    },
    onError: (_) async => teardown(),
  );
}

({VideoEncoder encoder, StreamSubscription<VideoFrame> sub}) _startVideoStream(
    RtpSender sender) {
  const width = 320, height = 240, framerate = 30;
  final PayloadPacketizer packetizer =
      _codec == 'h264' ? H264Packetizer() : Vp8Packetizer();
  final encoder = VideoEncoder(
    output: (chunk, _) {
      final rtpTs = (chunk.timestamp * 90) ~/ 1000;
      final parts = packetizer.packetize(
        chunk.data,
        isKeyFrame: chunk.type == EncodedVideoChunkType.key,
      );
      for (final (payload, marker) in parts) {
        sender.sendRtp(payload, marker: marker, timestamp: rtpTs);
      }
    },
    error: (e) => stderr.writeln('[sender] encoder error: $e'),
  );
  encoder.configure(VideoEncoderConfig(
    codec: _codec,
    width: width,
    height: height,
    bitrate: 400000,
    framerate: framerate.toDouble(),
    latencyMode: 'realtime',
  ));

  final source = FakeVideoSource(
      width: width, height: height, framerate: framerate.toDouble());
  var frameCount = 0;
  final sub = source.start().listen((frame) {
    encoder.encode(frame, VideoEncoderEncodeOptions(keyFrame: frameCount == 0));
    frame.close();
    frameCount++;
  });
  return (encoder: encoder, sub: sub);
}

void _pipeIncoming(RtpReceiver receiver, String codec) {
  final VideoPayloadDepacketizer depack =
      codec == 'h264' ? H264Depacketizer() : Vp8Depacketizer();
  var decoded = 0;
  var decoderConfigured = false;
  final decoder = VideoDecoder(
    output: (frame) {
      decoded++;
      if (decoded <= 3 || decoded % 30 == 0) {
        stdout.writeln('[sender] decoded #$decoded '
            '${frame.codedWidth}x${frame.codedHeight} '
            'ts=${frame.timestamp}');
      }
      frame.close();
    },
    error: (e) => stderr.writeln('[sender] decoder error: $e'),
  );

  receiver.onRtp.listen((rtp) {
    final chunk = depack.depacketize(
      rtp.payload,
      marker: rtp.marker,
      timestamp: rtp.timestamp,
    );
    if (chunk == null) return;
    if (!decoderConfigured) {
      if (chunk.type != EncodedVideoChunkType.key) return;
      decoder.configure(VideoDecoderConfig(codec: codec));
      decoderConfigured = true;
    }
    decoder.decode(chunk);
  });
}
