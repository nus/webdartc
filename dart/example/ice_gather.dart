/// ICE candidate gathering example.
///
/// Gathers host and server-reflexive (srflx) candidates using a STUN server,
/// then prints each candidate as an SDP a=candidate line.
///
/// Usage:
///   dart run example/ice_gather.dart
///   dart run example/ice_gather.dart stun:stun.l.google.com:19302
import 'dart:io';

import 'package:webdartc/webdartc.dart';

void main(List<String> args) async {
  final stunUrl = args.isNotEmpty ? args[0] : 'stun:stun.l.google.com:19302';

  final pc = PeerConnection(
    configuration: PeerConnectionConfiguration(
      iceServers: [IceServer(urls: [stunUrl])],
    ),
  );

  final candidates = <String>[];
  pc.onIceCandidate.listen((evt) {
    candidates.add(evt.candidate);
    final type = evt.candidate.contains('typ host')
        ? 'host'
        : evt.candidate.contains('typ srflx')
            ? 'srflx'
            : 'other';
    print('[$type] a=${evt.candidate}');
  });

  pc.createDataChannel('dummy');
  final offer = await pc.createOffer();
  await pc.setLocalDescription(offer);

  // Wait for STUN server response.
  await Future<void>.delayed(const Duration(seconds: 5));

  print('\n--- Summary ---');
  print('STUN server: $stunUrl');
  print('Candidates: ${candidates.length}');

  await pc.close();
  exit(0);
}
