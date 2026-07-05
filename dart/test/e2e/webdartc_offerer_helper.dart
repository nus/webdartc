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

import 'e2e_settings.dart';
import 'helper_ws_client.dart';

// ── Main ──────────────────────────────────────────────────────────────────────

void main(List<String> args) async {
  int port = 8080;
  int timeoutSec = 30;
  var closeChannel = false;
  var checkBuffered = false;
  for (final arg in args) {
    if (arg.startsWith('--port=')) {
      port = int.parse(arg.substring('--port='.length));
    } else if (arg.startsWith('--timeout=')) {
      timeoutSec = int.parse(arg.substring('--timeout='.length));
    } else if (arg == '--close-dc') {
      closeChannel = true;
    } else if (arg == '--check-buffered') {
      checkBuffered = true;
    }
  }

  final exitCode = await _run(port,
      timeoutSec: timeoutSec,
      closeChannel: closeChannel,
      checkBuffered: checkBuffered);
  exit(exitCode);
}

/// Verify the W3C back-pressure surface (PR for DataChannel.bufferedAmount):
/// bufferedAmount rose on send and, as Chrome acked, drained to 0 and fired
/// onBufferedAmountLow. Completes [done] with 0 on success, 1 on failure.
Future<void> _verifyBuffered(DataChannel dc, int afterSend,
    bool Function() lowFired, Completer<int> done) async {
  if (afterSend <= 0) {
    stderr.writeln('[offerer] bufferedAmount FAIL: did not rise on send '
        '(=$afterSend)');
    if (!done.isCompleted) done.complete(1);
    return;
  }
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (DateTime.now().isBefore(deadline)) {
    if (dc.bufferedAmount == 0 && lowFired()) {
      stdout.writeln('[offerer] bufferedAmount OK: rose to $afterSend, drained '
          'to 0, onBufferedAmountLow fired');
      if (!done.isCompleted) done.complete(0);
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 200));
  }
  stderr.writeln('[offerer] bufferedAmount FAIL: did not drain '
      '(now=${dc.bufferedAmount}, onBufferedAmountLow fired=${lowFired()})');
  if (!done.isCompleted) done.complete(1);
}

Future<int> _run(int sigPort,
    {int timeoutSec = 30,
    bool closeChannel = false,
    bool checkBuffered = false}) async {
  final ws = await HelperWsClient.connect(sigPort);
  ws.sendJson({'type': 'register', 'role': 'offerer'});

  final pc = PeerConnection(
    configuration: const PeerConnectionConfiguration(),
    settingEngine: e2eSettings,
  );
  pc.onIceConnectionStateChange.listen((state) {
    stderr.writeln('[offerer] ICE state: $state');
  });
  final dc = pc.createDataChannel('test');

  var textEchoed   = false;
  var binaryEchoed = false;
  final done = Completer<int>();

  // When --close-dc is set, after both echoes the offerer closes the data
  // channel and waits for its own onClose to fire (RFC 8831 §6.7). onClose
  // fires once *our* outgoing reset completes; the channel isn't fully torn
  // down both ways until we also answer Chrome's reciprocal reset request,
  // which is why the PeerConnection is kept alive briefly below.
  dc.onClose.listen((_) {
    stdout.writeln('[offerer] DataChannel onClose fired (our stream reset complete)');
    if (!done.isCompleted) done.complete(0);
  });

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

  // Expected payloads for echo verification. The multi-byte prefix
  // (emoji surrogate pair + Japanese) exercises the UTF-8 send/receive
  // path end-to-end through Chrome — the old UTF-16-code-unit encoding
  // would corrupt these and fail the echo match.
  final sentText = '🎉日本語テスト ${'A' * 1024}';
  final sentBin = Uint8List(64 * 1024);
  for (var i = 0; i < sentBin.length; i++) { sentBin[i] = i & 0xFF; }

  var bufferedAfterSend = 0;
  var bufferedLowFired = false;
  dc.onBufferedAmountLow.listen((_) => bufferedLowFired = true);

  dc.onOpen.listen((_) async {
    stdout.writeln('[offerer] DataChannel open — sending messages');
    dc.send(sentText);
    dc.sendBinary(sentBin);
    bufferedAfterSend = dc.bufferedAmount;
    stdout.writeln('[offerer] bufferedAmount after send = $bufferedAfterSend');
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
      if (closeChannel) {
        stdout.writeln('[offerer] echoes OK — closing data channel');
        dc.close(); // exit 0 deferred to dc.onClose (stream reset complete)
      } else if (checkBuffered) {
        // Echoes prove Chrome received (and SACKed) everything, so
        // bufferedAmount must have risen on send and drained to 0.
        unawaited(
            _verifyBuffered(dc, bufferedAfterSend, () => bufferedLowFired, done));
      } else {
        stdout.writeln('[offerer] PASS');
        done.complete(0);
      }
    }
  });

  // Create offer and send.
  final offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  stderr.writeln('[offerer] offer SDP:\n${offer.sdp}');
  ws.sendJson({'type': 'offer', 'sdp': offer.sdp});

  // Process signaling messages.
  ws.messages.listen((raw) async {
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
  });

  final result = await done.future.timeout(
    Duration(seconds: timeoutSec),
    onTimeout: () {
      stderr.writeln('[offerer] TIMEOUT');
      return 1;
    },
  );

  // We initiated the close: our onClose fires when *our* outgoing reset
  // completes, but Chrome only fires its onclose once we answer its
  // reciprocal Outgoing SSN Reset Request (RFC 8831 §6.7). Tearing the
  // PeerConnection down immediately can race that response away — Chrome's
  // request arrives after the transport is gone — leaving Chrome's onclose
  // (and the test's dcClosed wait) pending. Stay alive briefly so the SCTP
  // stack can respond and the bidirectional reset completes.
  if (closeChannel && result == 0) {
    await Future<void>.delayed(const Duration(seconds: 2));
  }

  await pc.close();
  await ws.close();
  return result;
}
