/// `getUserMedia` → PeerConnection example for macOS.
///
/// Pure-Dart sender that captures the system camera + microphone via
/// AVFoundation (no Flutter required) and streams them to a browser tab
/// over RTP/SRTP. The browser is purely receive-only.
///
/// Usage:
///   dart run example/getusermedia_call/server.dart \
///       [--port=8080] [--codec=vp8|vp9|h264]
///
/// Open http://127.0.0.1:<port> in Chrome and click Start. The first
/// run triggers the macOS TCC prompts for camera + microphone.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/src/media/macos/avf_capture_track.dart';
import 'package:webdartc/src/media/macos/avf_media_devices.dart';
import 'package:webdartc/src/codec/codec_support.dart';
import 'package:webdartc/webdartc.dart';

int _port = 8080;
String _codec = 'vp8';

Future<void> main(List<String> args) async {
  for (final a in args) {
    if (a.startsWith('--port=')) _port = int.parse(a.substring(7));
    if (a.startsWith('--codec=')) _codec = a.substring(8).toLowerCase();
  }
  if (_codec != 'vp8' && _codec != 'vp9' && _codec != 'h264') {
    stderr.writeln('Unsupported --codec=$_codec (expected vp8, vp9 or h264)');
    exit(2);
  }
  if (!Platform.isMacOS) {
    stderr.writeln('This example only runs on macOS (uses AVFoundation).');
    exit(64);
  }

  switch (_codec) {
    case 'vp8':
      registerVp8Codec();
    case 'vp9':
      registerVp9Codec();
    case 'h264':
      registerH264Codec();
  }
  registerOpusCodec();
  registerAvfMediaDevicesBackend();

  final server = await HttpServer.bind(InternetAddress.anyIPv4, _port);
  stdout.writeln(
      'getusermedia_call server listening on http://127.0.0.1:$_port '
      '(codec=$_codec)');
  stdout.writeln('Open the URL in Chrome and click Start.');

  await for (final req in server) {
    if (WebSocketTransformer.isUpgradeRequest(req)) {
      final ws = await WebSocketTransformer.upgrade(req);
      _handleWs(ws);
    } else {
      _serveHtml(req);
    }
  }
}

String _scriptDir() {
  final script = Platform.script.toFilePath();
  return script.substring(0, script.lastIndexOf('/'));
}

void _serveHtml(HttpRequest req) {
  final path = '${_scriptDir()}/index.html';
  String html;
  try {
    html = File(path).readAsStringSync();
  } on FileSystemException {
    req.response
      ..statusCode = 404
      ..write('index.html not found at $path')
      ..close();
    return;
  }
  req.response
    ..headers.contentType = ContentType.html
    ..write(html.replaceAll("params.get('port') || '8080'", "'$_port'"))
    ..close();
}

void _handleWs(WebSocket ws) {
  stdout.writeln('[ws] client connected');

  PeerConnection? pc;
  MediaStream? localStream;
  final subs = <StreamSubscription<void>>[];
  VideoEncoder? videoEncoder;
  AudioEncoder? audioEncoder;

  Future<void> teardown() async {
    for (final s in subs) {
      await s.cancel();
    }
    subs.clear();
    if (localStream != null) {
      for (final t in localStream!.getTracks()) {
        t.stop();
      }
      localStream = null;
    }
    videoEncoder?.close();
    videoEncoder = null;
    audioEncoder?.close();
    audioEncoder = null;
    await pc?.close();
    pc = null;
  }

  ws.listen(
    (data) async {
      if (data is! String) return;
      final msg = jsonDecode(data) as Map<String, dynamic>;
      switch (msg['type']) {
        case 'offer':
          stdout.writeln('[sig] offer received');
          pc = PeerConnection(
              configuration: const PeerConnectionConfiguration());

          pc!.addTransceiver('audio',
              direction: 'sendonly', preferredCodecs: ['opus']);
          pc!.addTransceiver('video',
              direction: 'sendonly',
              preferredCodecs: [_codec.toUpperCase()]);

          final audioSender =
              pc!.getSenders().firstWhere((s) => s.kind == 'audio');
          final videoSender =
              pc!.getSenders().firstWhere((s) => s.kind == 'video');
          stdout.writeln('[setup] audio ssrc=${audioSender.ssrc} '
              'pt=${audioSender.payloadType}; '
              'video ssrc=${videoSender.ssrc} pt=${videoSender.payloadType}');

          pc!.onIceCandidate.listen((evt) {
            ws.add(jsonEncode({
              'type': 'candidate',
              'candidate': {
                'candidate': evt.candidate,
                'sdpMid': evt.sdpMid,
                'sdpMLineIndex': evt.sdpMLineIndex,
              },
            }));
          });
          pc!.onIceConnectionStateChange.listen((s) => stdout.writeln('[ice] $s'));
          pc!.onConnectionStateChange.listen((s) async {
            stdout.writeln('[conn] $s');
            if (s == PeerConnectionState.connected && localStream == null) {
              await _startCapture(
                audioSender: audioSender,
                videoSender: videoSender,
                onStream: (stream) => localStream = stream,
                onVideoEncoder: (e) => videoEncoder = e,
                onAudioEncoder: (e) => audioEncoder = e,
                subs: subs,
              );
            }
          });

          await pc!.setRemoteDescription(SessionDescription(
            type: SessionDescriptionType.offer,
            sdp: msg['sdp'] as String,
          ));
          final answer = await pc!.createAnswer();
          await pc!.setLocalDescription(answer);
          ws.add(jsonEncode({'type': 'answer', 'sdp': answer.sdp}));
          stdout.writeln('[sig] answer sent');

        case 'candidate':
          final cand = msg['candidate'];
          if (cand is Map<String, dynamic> && pc != null) {
            await pc!.addIceCandidate(IceCandidateInit(
              candidate: (cand['candidate'] as String?) ?? '',
              sdpMid: (cand['sdpMid'] as String?) ?? '0',
              sdpMLineIndex: (cand['sdpMLineIndex'] as int?) ?? 0,
            ));
          }
      }
    },
    onDone: () async {
      stdout.writeln('[ws] client disconnected');
      await teardown();
    },
    onError: (_) async => teardown(),
  );
}

const _width = 640;
const _height = 480;
const _framerate = 30.0;
const _videoBitrate = 800000;
const _audioChannels = 1;
const _audioSampleRate = 48000;

Future<void> _startCapture({
  required RtpSender audioSender,
  required RtpSender videoSender,
  required void Function(MediaStream) onStream,
  required void Function(VideoEncoder) onVideoEncoder,
  required void Function(AudioEncoder) onAudioEncoder,
  required List<StreamSubscription<void>> subs,
}) async {
  stdout.writeln('[capture] starting getUserMedia');
  final stream = await MediaDevices.getUserMedia(MediaStreamConstraints(
    video: const MediaTrackConstraints(
      width: _width,
      height: _height,
      frameRate: _framerate,
    ),
    audio: const MediaTrackConstraints(
      sampleRate: _audioSampleRate,
      channelCount: _audioChannels,
    ),
  ));
  onStream(stream);

  final packetizer = videoPacketizerFor(_codec)!;
  var videoFrames = 0;
  final videoEncoder = VideoEncoder(
    output: (chunk, _) {
      // Video RTP timestamp clock is 90 kHz; encoder reports microseconds.
      final rtpTs = (chunk.timestamp * 90) ~/ 1000;
      final parts = packetizer.packetize(
        chunk.data,
        isKeyFrame: chunk.type == EncodedVideoChunkType.key,
      );
      for (final (payload, marker) in parts) {
        videoSender.sendRtp(payload, marker: marker, timestamp: rtpTs);
      }
    },
    error: (e) => stderr.writeln('[video] encoder error: $e'),
  );
  videoEncoder.configure(VideoEncoderConfig(
    codec: _codec,
    width: _width,
    height: _height,
    bitrate: _videoBitrate,
    framerate: _framerate,
    latencyMode: 'realtime',
  ));
  onVideoEncoder(videoEncoder);

  final videoTrack = stream.getVideoTracks().first as AvfCaptureVideoTrack;
  subs.add(videoTrack.onVideoFrame.listen((frame) {
    videoEncoder.encode(
      frame,
      VideoEncoderEncodeOptions(keyFrame: videoFrames == 0),
    );
    frame.close();
    videoFrames++;
    if (videoFrames % 60 == 0) {
      stdout.writeln('[video] encoded $videoFrames frames');
    }
  }));

  var audioPackets = 0;
  final audioEncoder = AudioEncoder(
    output: (chunk, _) {
      // sendRtp auto-increments by 960 samples (20 ms @ 48 kHz) when no
      // timestamp is passed — matches Opus's 20-ms frame cadence.
      audioSender.sendRtp(chunk.data);
      audioPackets++;
      if (audioPackets % 100 == 0) {
        stdout.writeln('[audio] sent $audioPackets Opus packets');
      }
    },
    error: (e) => stderr.writeln('[audio] encoder error: $e'),
  );
  audioEncoder.configure(const AudioEncoderConfig(
    codec: 'opus',
    sampleRate: _audioSampleRate,
    numberOfChannels: _audioChannels,
  ));
  onAudioEncoder(audioEncoder);

  final audioTrack = stream.getAudioTracks().first as AvfCaptureAudioTrack;
  subs.add(audioTrack.onAudioData.listen(audioEncoder.encode));

  stdout.writeln('[capture] pipelines started '
      '(${_width}x$_height @${_framerate}fps, '
      '${_audioSampleRate}Hz/${_audioChannels}ch)');
}
