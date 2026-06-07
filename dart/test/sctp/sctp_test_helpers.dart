import 'package:webdartc/webdartc.dart';

/// Drive two [SctpStateMachine]s through the full INIT / INIT-ACK /
/// COOKIE-ECHO / COOKIE-ACK handshake and return the established pair.
(SctpStateMachine, SctpStateMachine) establishSctpPair() {
  final client = SctpStateMachine(isClient: true);
  final server = SctpStateMachine(isClient: false);
  final ip = IpAddress.parse('127.0.0.1');
  const clientPort = 5000;
  const serverPort = 5001;

  final init = client.connect(remoteIp: ip, remotePort: serverPort);
  final initAck = server.processInput(init.value.outputPackets.first.data,
      remoteIp: ip, remotePort: clientPort);
  final cookieEcho = client.processInput(initAck.value.outputPackets.first.data,
      remoteIp: ip, remotePort: serverPort);
  final cookieAck = server.processInput(
      cookieEcho.value.outputPackets.first.data,
      remoteIp: ip,
      remotePort: clientPort);
  client.processInput(cookieAck.value.outputPackets.first.data,
      remoteIp: ip, remotePort: serverPort);
  return (client, server);
}
