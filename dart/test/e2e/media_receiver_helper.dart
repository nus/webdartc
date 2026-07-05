/// webdartc media receiver helper process for E2E tests.
///
/// Connects to the signaling server as offerer, adds a recvonly audio
/// transceiver, performs offer/answer exchange, waits for onTrack, then
/// verifies transceiver negotiation + getStats against the live stream.
/// Exits 0 on success, non-zero on failure (the reason is logged to stderr).
///
/// Usage:
///   dart run test/e2e/media_receiver_helper.dart --port=PORT
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:webdartc/webdartc.dart';

import 'e2e_settings.dart';
import 'helper_ws_client.dart';

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

/// Verify each transceiver got a negotiated `mid` + `currentDirection`
/// after Chrome's answer (PR #42). Returns true on success; on failure logs
/// and completes [done] with exit code 2.
bool _checkTransceivers(PeerConnection pc, Completer<int> done) {
  final txs = pc.getTransceivers();
  if (txs.isEmpty) {
    stderr.writeln('[media-receiver] FAIL: no transceivers after answer');
    if (!done.isCompleted) done.complete(2);
    return false;
  }
  for (final t in txs) {
    if (t.mid == null) {
      stderr.writeln('[media-receiver] FAIL: ${t.kind} transceiver has no '
          'mid after answer');
      if (!done.isCompleted) done.complete(2);
      return false;
    }
    if (t.currentDirection != RtpTransceiverDirection.recvonly) {
      stderr.writeln('[media-receiver] FAIL: ${t.kind} currentDirection='
          '${t.currentDirection} (expected recvonly)');
      if (!done.isCompleted) done.complete(2);
      return false;
    }
  }
  stdout.writeln('[media-receiver] transceivers negotiated: ${txs.map((t) =>
      '${t.kind} mid=${t.mid} ${t.currentDirection!.name}').join(', ')}');
  return true;
}

/// Poll `getStats()` until the inbound stream and the SR-derived
/// remote-outbound stat for [ssrc] are populated, then assert their fields
/// (PR #40). Completes [done] with 0 on success, non-zero on failure (the
/// specific bad field / timeout is written to stderr).
Future<void> _verifyStats(
    PeerConnection pc, int ssrc, String kind, Completer<int> done) async {
  // Stat ids are deterministic and SSRC-derived.
  final inboundId = 'inbound-rtp-$ssrc';
  final remoteOutId = 'remote-outbound-rtp-$ssrc';
  // Chrome emits its first RTCP SR a few seconds in; poll generously.
  final deadline = DateTime.now().add(const Duration(seconds: 20));
  while (DateTime.now().isBefore(deadline) && !done.isCompleted) {
    final report = await pc.getStats();
    final inbound = report[inboundId] as InboundRtpStats?;
    final remoteOut = report[remoteOutId] as RemoteOutboundRtpStats?;

    if (inbound != null && inbound.packetsReceived > 0 && remoteOut != null) {
      final problems = <String>[];
      // Inbound RTP (real Chrome media → real interarrival jitter).
      if (inbound.kind != kind) {
        problems.add('inbound.kind=${inbound.kind} expected $kind');
      }
      if (inbound.jitter < 0) problems.add('inbound.jitter=${inbound.jitter}');
      if (inbound.codecId == null ||
          report[inbound.codecId!] is! CodecStats) {
        problems.add('inbound.codecId=${inbound.codecId} not a codec');
      }
      // remote-outbound-rtp (from the peer's Sender Reports). packetsSent
      // is the SR's sender packet count, which is browser/timing-dependent
      // (Firefox's first SR reports 0, Chrome ~120); only require it to be
      // a sane non-negative count, not strictly positive.
      if (remoteOut.localId != inbound.id) {
        problems.add('remoteOut.localId=${remoteOut.localId} != ${inbound.id}');
      }
      if (remoteOut.packetsSent < 0) {
        problems.add('remoteOut.packetsSent=${remoteOut.packetsSent}');
      }
      if (remoteOut.remoteTimestamp == null) {
        problems.add('remoteOut.remoteTimestamp null');
      }
      if (remoteOut.reportsReceived <= 0) {
        problems.add('remoteOut.reportsReceived=${remoteOut.reportsReceived}');
      }

      if (problems.isEmpty) {
        stdout.writeln('[media-receiver] getStats OK: inbound '
            'packets=${inbound.packetsReceived} jitter=${inbound.jitter} '
            'lost=${inbound.packetsLost} codec=${inbound.codecId}; '
            'remote-outbound packetsSent=${remoteOut.packetsSent} '
            'reports=${remoteOut.reportsReceived}');
        if (!done.isCompleted) done.complete(0);
      } else {
        stderr.writeln('[media-receiver] getStats FAIL: ${problems.join('; ')}');
        if (!done.isCompleted) done.complete(1);
      }
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 500));
  }
  if (!done.isCompleted) {
    stderr.writeln('[media-receiver] getStats TIMEOUT: inbound/remote-outbound '
        'not populated for ssrc=$ssrc within window');
    done.complete(1);
  }
}

Future<int> _run(int sigPort, String kind) async {
  final ws = await HelperWsClient.connect(sigPort);
  ws.sendJson({'type': 'register', 'role': 'offerer'});

  final pc = PeerConnection(
    configuration: const PeerConnectionConfiguration(),
    settingEngine: e2eSettings,
  );
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
  // Once a track is flowing, verify getStats against the real Chrome
  // stream (inbound jitter/loss + the SR-derived remote-outbound-rtp).
  var statsStarted = false;
  pc.onTrack.listen((evt) {
    stdout.writeln('[media-receiver] onTrack: kind=${evt.kind} ssrc=${evt.ssrc}');
    if (!statsStarted) {
      statsStarted = true;
      unawaited(_verifyStats(pc, evt.ssrc, evt.kind, done));
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
        // Verify W3C RtpTransceiver negotiation against Chrome (PR #42):
        // we offered recvonly, Chrome answers sendonly, so every
        // transceiver must now carry a mid and currentDirection=recvonly.
        if (!_checkTransceivers(pc, done)) return;
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
