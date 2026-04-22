/// Browser ↔ Flutter bidirectional video_call demo (macOS).
///
/// The Flutter app is a WebRTC peer: it connects to the video_call
/// signaling server, sends a FakeVideoSource stream (H.264 via
/// VideoToolbox), and renders the browser's incoming stream via
/// ShaderVideoRenderer.
///
/// Signaling server and browser client come from
/// `dart/example/video_call/` (run those first). This app knows the
/// server's port from the `WEBDARTC_PORT` env var (default `8080`).
///
/// Run:
/// ```
/// # terminal 1
/// cd dart
/// dart run example/video_call/bin/server.dart --port=8080
/// # open http://127.0.0.1:8080/?bidir=1 in Chrome
///
/// # terminal 2
/// cd flutter/example
/// WEBDARTC_PORT=8080 flutter run -d macos
/// ```
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:webdartc/rtp/packetizer.dart';
import 'package:webdartc/webdartc.dart';
import 'package:webdartc_flutter/webdartc_flutter.dart';

void main() => runApp(const _App());

class _App extends StatelessWidget {
  const _App();
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'webdartc video_call (bidir)',
        theme: ThemeData.dark(),
        home: const _Demo(),
      );
}

class _Demo extends StatefulWidget {
  const _Demo();
  @override
  State<_Demo> createState() => _DemoState();
}

class _DemoState extends State<_Demo> {
  static const _width = 320;
  static const _height = 240;
  static const _fps = 30;

  late final ShaderVideoRenderer _localRenderer;
  late final ShaderVideoRenderer _remoteRenderer;
  PeerConnection? _pc;
  WebSocket? _ws;
  VideoEncoder? _encoder;
  VideoDecoder? _decoder;
  StreamSubscription<VideoFrame>? _sourceSub;

  int _framesOut = 0; // sent (encoded → RTP)
  int _framesIn = 0; // received (decoded from browser)
  String _status = 'initializing…';

  @override
  void initState() {
    super.initState();
    _localRenderer = ShaderVideoRenderer();
    _remoteRenderer = ShaderVideoRenderer();
    unawaited(_start());
  }

  Future<void> _start() async {
    registerH264Codec();

    final port = int.parse(
        Platform.environment['WEBDARTC_PORT'] ?? '8080');
    try {
      _ws = await WebSocket.connect('ws://127.0.0.1:$port')
          .timeout(const Duration(seconds: 5));
    } catch (e) {
      setState(() => _status = 'ws connect failed: $e');
      return;
    }
    stdout.writeln('[flutter] ws connected port=$port');

    final pc = PeerConnection(
        configuration: const PeerConnectionConfiguration());
    _pc = pc;

    pc.addTransceiver('video',
        direction: 'sendrecv', preferredCodecs: ['H264']);
    final sender =
        pc.getSenders().firstWhere((s) => s.kind == 'video');

    pc.onTrack.listen((evt) {
      if (evt.kind != 'video') return;
      stdout.writeln('[flutter] onTrack ssrc=${evt.ssrc}');
      _wireIncomingTrack(evt.receiver);
    });

    pc.onIceCandidate.listen((evt) {
      _ws?.add(jsonEncode({
        'type': 'candidate',
        'candidate': {
          'candidate': evt.candidate,
          'sdpMid': evt.sdpMid,
          'sdpMLineIndex': evt.sdpMLineIndex,
        }
      }));
    });
    pc.onConnectionStateChange.listen((s) {
      if (!mounted) return;
      setState(() => _status = 'pc=$s');
    });

    _ws!.listen((data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type'] as String?) {
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
    });

    final offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    _ws!.add(jsonEncode({'type': 'offer', 'sdp': offer.sdp}));

    await pc.onConnectionStateChange
        .firstWhere((s) => s == PeerConnectionState.connected)
        .timeout(const Duration(seconds: 30));
    stdout.writeln('[flutter] connected — starting video');
    if (mounted) setState(() => _status = 'streaming');

    // Outgoing: FakeVideoSource → VT encoder → RTP
    final packetizer = H264Packetizer();
    _encoder = VideoEncoder(
      output: (chunk, _) {
        final rtpTs = (chunk.timestamp * 90) ~/ 1000; // us → 90 kHz
        for (final (payload, marker) in packetizer.packetize(
          chunk.data,
          isKeyFrame: chunk.type == EncodedVideoChunkType.key,
        )) {
          sender.sendRtp(payload, marker: marker, timestamp: rtpTs);
        }
        _framesOut++;
        if (_framesOut == 1 || _framesOut % 30 == 0) {
          stdout.writeln('[flutter] sent=$_framesOut');
        }
      },
      error: (e) => stderr.writeln('[flutter] encoder error: $e'),
    );
    _encoder!.configure(const VideoEncoderConfig(
      codec: 'h264',
      width: _width,
      height: _height,
      bitrate: 300000,
      framerate: 30,
      latencyMode: 'realtime',
    ));

    final source = FakeVideoSource(
      width: _width,
      height: _height,
      framerate: _fps.toDouble(),
    );
    var idx = 0;
    _sourceSub = source.start().listen((frame) {
      _localRenderer.render(frame);
      _encoder!.encode(
          frame, VideoEncoderEncodeOptions(keyFrame: idx == 0));
      frame.close();
      idx++;
    });
  }

  void _wireIncomingTrack(RtpReceiver receiver) {
    final depack = H264Depacketizer();
    var configured = false;
    _decoder = VideoDecoder(
      output: (frame) {
        _framesIn++;
        _remoteRenderer.render(frame);
        frame.close();
        if (_framesIn == 1 || _framesIn % 30 == 0) {
          stdout.writeln('[flutter] recv=$_framesIn');
        }
        if (mounted && _framesIn % 30 == 0) setState(() {});
      },
      error: (e) => stderr.writeln('[flutter] decoder error: $e'),
    );
    receiver.onRtp.listen((rtp) {
      final chunk = depack.depacketize(
        rtp.payload,
        marker: rtp.marker,
        timestamp: rtp.timestamp,
      );
      if (chunk == null) return;
      if (!configured) {
        if (chunk.type != EncodedVideoChunkType.key) return;
        _decoder!.configure(const VideoDecoderConfig(codec: 'h264'));
        configured = true;
      }
      _decoder!.decode(chunk);
    });
  }

  @override
  void dispose() {
    _sourceSub?.cancel();
    _encoder?.close();
    _decoder?.close();
    _pc?.close();
    _ws?.close();
    unawaited(_localRenderer.dispose());
    unawaited(_remoteRenderer.dispose());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
          title: Text('webdartc — $_status  '
              'sent=$_framesOut recv=$_framesIn')),
      body: Center(
        child: Row(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _labeledVideo(
              label: 'local  (sent=$_framesOut)',
              renderer: _localRenderer,
              placeholderText: 'waiting for local video…',
            ),
            const SizedBox(width: 16),
            _labeledVideo(
              label: 'remote (recv=$_framesIn)',
              renderer: _remoteRenderer,
              placeholderText: 'waiting for remote video…',
            ),
          ],
        ),
      ),
    );
  }

  Widget _labeledVideo({
    required String label,
    required ShaderVideoRenderer renderer,
    required String placeholderText,
  }) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(bottom: 4),
          child: Text(label,
              style: const TextStyle(
                  color: Colors.white70,
                  fontFamily: 'Menlo',
                  fontSize: 13)),
        ),
        SizedBox(
          width: _width.toDouble(),
          height: _height.toDouble(),
          child: VideoRendererWidget(
            renderer: renderer,
            placeholder: ColoredBox(
              color: Colors.black,
              child: Center(
                child: Text(
                  placeholderText,
                  style: const TextStyle(color: Colors.white54),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}
