/// webdartc Flutter demo — Ayame-compatible WebRTC peer.
///
/// Joins a 1-on-1 room via the OpenAyame signaling protocol
/// (https://github.com/OpenAyame/ayame-spec) and runs a bidirectional
/// H.264 video call against a browser or another Flutter peer.
///
/// On launch the app starts an embedded signaling relay on port 8080
/// (see `embedded_signaling.dart`), so `flutter run` alone is enough:
/// open the URL shown on the form (`http://127.0.0.1:8080/`) in a
/// browser and press **Join**. If port 8080 is already taken (an
/// external `dart/example/signaling/server.dart`, or another instance
/// of this app), the embedded relay is skipped and the app just joins
/// the existing one.
///
/// The form pre-fills the WebSocket URL, the room id, and the optional
/// signaling key from `--dart-define=AYAME_URL=...` (likewise
/// `AYAME_ROOM`, `AYAME_SIGNALING_KEY`).
/// Setting `WEBDARTC_PORT=N` in the environment skips both the form and
/// the embedded relay, and auto-joins the local
/// `dart/example/signaling/server.dart` running on that port (room
/// defaults to `webdartc-demo`) — used by the
/// `flutter_video_call_bidir_test.dart` e2e harness.
///
/// Run (macOS):
/// ```
/// cd flutter/example
/// flutter run -d macos
/// # or against a hosted Ayame:
/// flutter run -d macos --dart-define=AYAME_URL=wss://ayame.example.com/signaling
/// ```
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/material.dart';
// ignore: implementation_imports — H264Packetizer (send path) is internal API
import 'package:webdartc/src/rtp/packetizer.dart';
import 'package:webdartc/webdartc.dart';
import 'package:webdartc_flutter/webdartc_flutter.dart';

import 'embedded_signaling.dart';

void main() => runApp(const _App());

class _App extends StatelessWidget {
  const _App();
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'webdartc Ayame demo',
        theme: ThemeData.dark(),
        home: const _Home(),
      );
}

/// Holds either the connection form or the active call view.
class _Home extends StatefulWidget {
  const _Home();
  @override
  State<_Home> createState() => _HomeState();
}

class _HomeState extends State<_Home> {
  /// Active call config. `null` means we are showing the form.
  _AyameConfig? _activeConfig;

  /// Most recent config — survives Leave so the form can pre-fill on
  /// re-entry.
  _AyameConfig? _lastConfig;

  /// In-app relay so `flutter run` alone suffices. `null` while
  /// starting, or when port 8080 was taken / `WEBDARTC_PORT` is set.
  EmbeddedSignalingServer? _server;

  /// Browser-reachable URLs of [_server]; empty means "not serving".
  List<String> _serverUrls = const [];

  /// Form pre-fill pointing at [_server] when it landed on a fallback
  /// port (8080 was taken) and no explicit `AYAME_URL` was given.
  _AyameConfig? _embeddedDefault;

  @override
  void initState() {
    super.initState();
    // `WEBDARTC_PORT=N` in the environment auto-joins the local
    // signaling server on port N, room defaults to `webdartc-demo`.
    // Used by the e2e harness, which can't drive the form UI and
    // brings its own relay — don't start the embedded one.
    final portEnv = Platform.environment['WEBDARTC_PORT'];
    if (portEnv != null && portEnv.isNotEmpty) {
      _activeConfig = _AyameConfig(
        url: 'ws://127.0.0.1:$portEnv/signaling',
        room: 'webdartc-demo',
        signalingKey: '',
      );
      return;
    }
    unawaited(_startEmbeddedServer());
  }

  Future<void> _startEmbeddedServer() async {
    final server = await EmbeddedSignalingServer.start();
    if (server == null) {
      stdout.writeln('[signaling] all candidate ports busy — '
          'assuming an external relay on ws://127.0.0.1:8080/signaling');
      return;
    }
    final urls = await server.urls();
    stdout.writeln('[signaling] embedded relay on ${urls.join(' ')}');
    if (!mounted) {
      await server.close();
      return;
    }
    setState(() {
      _server = server;
      _serverUrls = urls;
      // 8080 was taken by something else (e.g. an unrelated dev server
      // holding only loopback) — point the form at the port we got,
      // unless the user explicitly chose a URL via --dart-define.
      const explicitUrl =
          String.fromEnvironment('AYAME_URL', defaultValue: '');
      if (server.port != 8080 && explicitUrl.isEmpty) {
        _embeddedDefault = _AyameConfig(
          url: 'ws://127.0.0.1:${server.port}/signaling',
          room: 'webdartc-demo',
          signalingKey: '',
        );
      }
    });
  }

  @override
  void dispose() {
    unawaited(_server?.close());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final active = _activeConfig;
    if (active == null) {
      return _ConfigForm(
        // Re-key when the embedded relay settles on a fallback port so
        // the pre-filled URL field picks it up.
        key: ValueKey(_embeddedDefault?.url),
        initial: _lastConfig ?? _embeddedDefault,
        serverUrls: _serverUrls,
        onSubmit: (cfg) => setState(() => _activeConfig = cfg),
      );
    }
    return _CallView(
      key: ValueKey(active.url + active.room),
      config: active,
      onLeave: () => setState(() {
        _lastConfig = active;
        _activeConfig = null;
      }),
    );
  }
}

class _AyameConfig {
  const _AyameConfig({
    required this.url,
    required this.room,
    required this.signalingKey,
  });

  final String url;
  final String room;
  final String signalingKey;
}

// ── Connection form ──────────────────────────────────────────────────────

class _ConfigForm extends StatefulWidget {
  const _ConfigForm({
    super.key,
    required this.onSubmit,
    this.initial,
    this.serverUrls = const [],
  });
  final ValueChanged<_AyameConfig> onSubmit;

  /// Pre-filled values (e.g. the last submitted config). Falls back to
  /// `--dart-define` defaults when null.
  final _AyameConfig? initial;

  /// URLs of the embedded signaling relay, shown so the user knows what
  /// to open in a browser. Empty when the relay isn't serving (port
  /// taken by an external one).
  final List<String> serverUrls;
  @override
  State<_ConfigForm> createState() => _ConfigFormState();
}

class _ConfigFormState extends State<_ConfigForm> {
  static const String _defaultUrl = String.fromEnvironment('AYAME_URL',
      defaultValue: 'ws://127.0.0.1:8080/signaling');
  static const String _defaultRoom =
      String.fromEnvironment('AYAME_ROOM', defaultValue: 'webdartc-demo');
  static const String _defaultSignalingKey =
      String.fromEnvironment('AYAME_SIGNALING_KEY', defaultValue: '');

  late final TextEditingController _urlCtl;
  late final TextEditingController _roomCtl;
  late final TextEditingController _keyCtl;
  final _formKey = GlobalKey<FormState>();

  @override
  void initState() {
    super.initState();
    final init = widget.initial;
    _urlCtl = TextEditingController(text: init?.url ?? _defaultUrl);
    _roomCtl = TextEditingController(text: init?.room ?? _defaultRoom);
    _keyCtl = TextEditingController(
        text: init?.signalingKey ?? _defaultSignalingKey);
  }

  @override
  void dispose() {
    _urlCtl.dispose();
    _roomCtl.dispose();
    _keyCtl.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) return;
    widget.onSubmit(_AyameConfig(
      url: _urlCtl.text.trim(),
      room: _roomCtl.text.trim(),
      signalingKey: _keyCtl.text.trim(),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('webdartc Ayame demo')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 480),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Form(
              key: _formKey,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (widget.serverUrls.isNotEmpty) ...[
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        border: Border.all(color: Colors.white24),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text('Embedded signaling relay is running.\n'
                              'Open in a browser (grant camera), then Join:'),
                          const SizedBox(height: 6),
                          for (final url in widget.serverUrls)
                            SelectableText(url,
                                style: const TextStyle(
                                    fontFamily: 'Menlo',
                                    color: Colors.lightGreenAccent)),
                        ],
                      ),
                    ),
                    const SizedBox(height: 16),
                  ],
                  TextFormField(
                    controller: _urlCtl,
                    decoration: const InputDecoration(
                      labelText: 'Signaling URL',
                      hintText: 'ws://host:3000/signaling',
                    ),
                    autocorrect: false,
                    validator: (v) {
                      final t = v?.trim() ?? '';
                      if (t.isEmpty) return 'URL is required';
                      if (!t.startsWith('ws://') && !t.startsWith('wss://')) {
                        return 'Must start with ws:// or wss://';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: 12),
                  TextFormField(
                    controller: _roomCtl,
                    decoration: const InputDecoration(labelText: 'Room ID'),
                    autocorrect: false,
                    validator: (v) =>
                        (v?.trim().isEmpty ?? true) ? 'Required' : null,
                  ),
                  const SizedBox(height: 12),
                  TextFormField(
                    controller: _keyCtl,
                    decoration: const InputDecoration(
                      labelText: 'Signaling key (optional)',
                    ),
                    autocorrect: false,
                    obscureText: true,
                  ),
                  const SizedBox(height: 24),
                  FilledButton(
                    onPressed: _submit,
                    child: const Padding(
                      padding: EdgeInsets.symmetric(vertical: 12),
                      child: Text('Join'),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ── Call view ────────────────────────────────────────────────────────────

class _CallView extends StatefulWidget {
  const _CallView({
    super.key,
    required this.config,
    required this.onLeave,
  });

  final _AyameConfig config;
  final VoidCallback onLeave;

  @override
  State<_CallView> createState() => _CallViewState();
}

class _CallViewState extends State<_CallView> {
  static const _width = 320;
  static const _height = 240;
  static const _fps = 30;

  late final ShaderVideoRenderer _localRenderer;
  late final ShaderVideoRenderer _remoteRenderer;
  PeerConnection? _pc;
  WebSocket? _ws;
  VideoEncoder? _encoder;
  StreamSubscription<VideoFrame>? _sourceSub;
  StreamSubscription<VideoFrame>? _remoteSub;

  /// True when *we* should send the offer (the room already had a peer
  /// when we registered — Ayame `isExistClient: true`).
  bool _isOfferer = false;
  String _clientId = '';
  int _framesOut = 0;
  int _framesIn = 0;
  String _status = 'initializing…';

  @override
  void initState() {
    super.initState();
    _localRenderer = ShaderVideoRenderer();
    _remoteRenderer = ShaderVideoRenderer();
    _clientId = _randomClientId();
    unawaited(_start());
  }

  Future<void> _start() async {
    // Every platform now has an H.264 backend (macOS/iOS=VideoToolbox,
    // Android=MediaCodec, desktop=OpenH264), so register H.264 everywhere.
    // Android additionally registers Opus for audio.
    registerH264Codec();
    if (Platform.isAndroid) registerOpusCodec();
    if (mounted) setState(() => _status = 'connecting ${widget.config.url}');

    try {
      _ws = await WebSocket.connect(widget.config.url)
          .timeout(const Duration(seconds: 10));
    } catch (e) {
      if (mounted) setState(() => _status = 'ws connect failed: $e');
      return;
    }
    stdout.writeln('[flutter] ws connected room=${widget.config.room} '
        'client=$_clientId');
    if (mounted) {
      setState(() => _status = 'registering room=${widget.config.room}');
    }

    _ws!.add(jsonEncode({
      'type': 'register',
      'roomId': widget.config.room,
      'clientId': _clientId,
      if (widget.config.signalingKey.isNotEmpty)
        'signalingKey': widget.config.signalingKey,
    }));

    _ws!.listen(_onSignalingMessage,
        onDone: () => stdout.writeln('[flutter] ws closed'),
        onError: (Object e) => stderr.writeln('[flutter] ws error: $e'));
  }

  Future<void> _onSignalingMessage(dynamic data) async {
    if (data is! String) return;
    final msg = jsonDecode(data) as Map<String, dynamic>;
    switch (msg['type'] as String?) {
      case 'accept':
        await _onAccept(msg);
      case 'reject':
        final reason = msg['reason'] as String? ?? 'unknown';
        stderr.writeln('[flutter] rejected: $reason');
        if (mounted) setState(() => _status = 'rejected: $reason');
      case 'offer':
        await _onRemoteSdp(msg, SessionDescriptionType.offer);
      case 'answer':
        await _onRemoteSdp(msg, SessionDescriptionType.answer);
      case 'candidate':
        await _onCandidate(msg);
      case 'ping':
        _ws?.add(jsonEncode({'type': 'pong'}));
      case 'bye':
        stdout.writeln('[flutter] peer left');
        if (mounted) setState(() => _status = 'peer left');
    }
  }

  Future<void> _onAccept(Map<String, dynamic> msg) async {
    _isOfferer = (msg['isExistClient'] as bool?) ?? false;
    final iceServers = _parseIceServers(msg['iceServers']);
    stdout.writeln('[flutter] accepted (offerer=$_isOfferer, '
        'iceServers=${iceServers.length})');

    // This demo registers codecs selectively above (Android: VP8+Opus,
    // desktop: H.264), so opt out of auto-registration to keep that control.
    final pc = PeerConnection(
        configuration: PeerConnectionConfiguration(iceServers: iceServers),
        autoRegisterCodecs: false);
    _pc = pc;

    pc.addTransceiver('video',
        direction: 'sendrecv', preferredCodecs: const ['H264']);
    final sender = pc.getSenders().firstWhere((s) => s.kind == 'video');

    pc.onIceCandidate.listen((evt) {
      _ws?.add(jsonEncode({
        'type': 'candidate',
        'ice': {
          'candidate': evt.candidate,
          'sdpMid': evt.sdpMid,
          'sdpMLineIndex': evt.sdpMLineIndex,
        },
      }));
    });

    pc.onTrack.listen((evt) {
      if (evt.kind != 'video') return;
      stdout.writeln('[flutter] onTrack ssrc=${evt.ssrc}');
      _wireIncomingTrack(evt.track);
    });

    pc.onConnectionStateChange.listen((s) {
      stdout.writeln('[flutter] PC: $s');
      if (mounted) setState(() => _status = 'pc=$s');
      if (s == PeerConnectionState.connected && _encoder == null) {
        _startSendingVideo(sender);
      }
    });

    if (_isOfferer) {
      final offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      stdout.writeln('[flutter] sending offer');
      _ws?.add(jsonEncode({'type': 'offer', 'sdp': offer.sdp}));
    }
    if (mounted) {
      setState(() => _status = _isOfferer ? 'sent offer' : 'waiting for offer');
    }
  }

  Future<void> _onRemoteSdp(
      Map<String, dynamic> msg, SessionDescriptionType type) async {
    final pc = _pc;
    if (pc == null) return;
    await pc.setRemoteDescription(
        SessionDescription(type: type, sdp: msg['sdp'] as String));
    if (type == SessionDescriptionType.offer) {
      final answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      stdout.writeln('[flutter] sending answer');
      _ws?.add(jsonEncode({'type': 'answer', 'sdp': answer.sdp}));
    }
  }

  Future<void> _onCandidate(Map<String, dynamic> msg) async {
    final pc = _pc;
    final ice = msg['ice'];
    if (pc == null || ice is! Map<String, dynamic>) return;
    await pc.addIceCandidate(IceCandidateInit(
      candidate: (ice['candidate'] as String?) ?? '',
      sdpMid: (ice['sdpMid'] as String?) ?? '0',
      sdpMLineIndex: (ice['sdpMLineIndex'] as int?) ?? 0,
    ));
  }

  void _startSendingVideo(RtpSender sender) {
    final packetizer = H264Packetizer();
    _encoder = VideoEncoder(
      output: (chunk, _) {
        final rtpTs = (chunk.timestamp * 90) ~/ 1000; // µs → 90 kHz
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
        width: _width, height: _height, framerate: _fps.toDouble());
    var idx = 0;
    _sourceSub = source.start().listen((frame) {
      _localRenderer.render(frame);
      _encoder!.encode(
          frame, VideoEncoderEncodeOptions(keyFrame: idx == 0));
      frame.close();
      idx++;
      if (mounted && idx % _fps == 0) setState(() {});
    });
  }

  void _wireIncomingTrack(MediaStreamTrack? track) {
    if (track == null) {
      stderr.writeln('[flutter] onTrack: no decoder for negotiated codec');
      return;
    }
    // The track decodes internally (jitter buffer → depacketize → decode);
    // subscribing to onVideoFrame starts that pipeline and yields ready-to-
    // render frames. The codec is resolved from SDP, so this works for VP8
    // (Android) and H.264 (desktop) alike — no manual depacketizer choice.
    _remoteSub = track.onVideoFrame.listen((frame) {
      _framesIn++;
      if (_framesIn == 1 || _framesIn % 30 == 0) {
        stdout.writeln('[flutter] recv=$_framesIn');
      }
      _remoteRenderer.render(frame);
      frame.close();
    });
  }

  @override
  void dispose() {
    _sourceSub?.cancel();
    _remoteSub?.cancel();
    _encoder?.close();
    _pc?.close();
    try {
      _ws?.add(jsonEncode({'type': 'bye'}));
    } catch (_) {}
    _ws?.close();
    unawaited(_localRenderer.dispose());
    unawaited(_remoteRenderer.dispose());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('webdartc ↔ Ayame — $_status  '
            'sent=$_framesOut recv=$_framesIn'),
        actions: [
          TextButton.icon(
            onPressed: widget.onLeave,
            icon: const Icon(Icons.logout),
            label: const Text('Leave'),
          ),
        ],
      ),
      body: Center(
        child: Row(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _labeledVideo(
              label: 'local  (sent=$_framesOut)',
              renderer: _localRenderer,
              placeholderText: 'starting local video…',
            ),
            const SizedBox(width: 16),
            _labeledVideo(
              label: 'remote (recv=$_framesIn)',
              renderer: _remoteRenderer,
              placeholderText: 'waiting for peer…',
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
                  fontSize: 12)),
        ),
        Container(
          width: _width.toDouble(),
          height: _height.toDouble(),
          decoration: BoxDecoration(
              color: Colors.black, border: Border.all(color: Colors.white24)),
          child: VideoRendererWidget(
            renderer: renderer,
            placeholder: ColoredBox(
              color: Colors.black,
              child: Center(
                child: Text(placeholderText,
                    style: const TextStyle(color: Colors.white38)),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// Convert Ayame's `iceServers` array (W3C-shaped) into webdartc's
/// `IceServer` records. Accepts either a single-string `urls` field or an
/// array of strings.
List<IceServer> _parseIceServers(Object? raw) {
  if (raw is! List) return const [];
  final out = <IceServer>[];
  for (final entry in raw) {
    if (entry is! Map) continue;
    final urls = entry['urls'];
    final List<String> urlList;
    if (urls is String) {
      urlList = [urls];
    } else if (urls is List) {
      urlList = urls.whereType<String>().toList();
    } else {
      continue;
    }
    if (urlList.isEmpty) continue;
    out.add(IceServer(
      urls: urlList,
      username: entry['username'] as String?,
      credential: entry['credential'] as String?,
    ));
  }
  return out;
}

String _randomClientId() {
  final r = Random.secure();
  final tail = List.generate(8, (_) => r.nextInt(36).toRadixString(36)).join();
  return 'webdartc-$tail';
}
