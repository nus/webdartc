/// Shared loopback handshake harness for two in-process PeerConnections.
library;

import 'package:webdartc/webdartc.dart';

/// Settings for the loopback handshake: bind to `127.0.0.1`, allow loopback
/// host candidates, no STUN/TURN.
const kLoopbackSetting = SettingEngine(
  bindAddresses: ['127.0.0.1'],
  includeLoopbackCandidate: true,
);

/// Wire bidirectional trickle-ICE forwarding between two loopback PCs.
void wireTrickle(PeerConnection pcA, PeerConnection pcB) {
  pcA.onIceCandidate.listen((evt) => pcB.addIceCandidate(IceCandidateInit(
        candidate: evt.candidate,
        sdpMid: evt.sdpMid,
        sdpMLineIndex: evt.sdpMLineIndex,
      )));
  pcB.onIceCandidate.listen((evt) => pcA.addIceCandidate(IceCandidateInit(
        candidate: evt.candidate,
        sdpMid: evt.sdpMid,
        sdpMLineIndex: evt.sdpMLineIndex,
      )));
}

/// Construct two PCs, wire trickle forwarding, run the offer/answer dance,
/// and wait until both reach `connected`. Optional callbacks let the caller
/// mutate each PC before the SDP exchange — separate for A and B so an
/// asymmetric setup (e.g. DataChannel on offerer only) is expressible.
Future<(PeerConnection, PeerConnection)> handshakeLoopback({
  void Function(PeerConnection pc)? configureA,
  void Function(PeerConnection pc)? configureB,
  Duration connectedTimeout = const Duration(seconds: 20),
}) async {
  final pcA = PeerConnection(
    configuration: PeerConnectionConfiguration(),
    settingEngine: kLoopbackSetting,
  );
  final pcB = PeerConnection(
    configuration: PeerConnectionConfiguration(),
    settingEngine: kLoopbackSetting,
  );
  // Subscribe BEFORE the SDP dance: onConnectionStateChange is a broadcast
  // stream that drops events for late subscribers, and on loopback the
  // handshake can race ahead of our subscription.
  final aConnected = pcA.onConnectionStateChange
      .firstWhere((s) => s == PeerConnectionState.connected);
  final bConnected = pcB.onConnectionStateChange
      .firstWhere((s) => s == PeerConnectionState.connected);
  wireTrickle(pcA, pcB);
  if (configureA != null) configureA(pcA);
  if (configureB != null) configureB(pcB);
  final offer = await pcA.createOffer();
  await pcA.setLocalDescription(offer);
  await pcB.setRemoteDescription(offer);
  final answer = await pcB.createAnswer();
  await pcB.setLocalDescription(answer);
  await pcA.setRemoteDescription(answer);
  await Future.wait([aConnected, bConnected]).timeout(connectedTimeout);
  return (pcA, pcB);
}
