/// On Windows, a UDP send whose failure surfaces asynchronously (errno
/// 1214 ERROR_BAD_NET_NAME / 1231 NETWORK_UNREACHABLE — routine for the
/// cross-interface pairs ICE probes on a multi-NIC host) is delivered as
/// an error event on the socket, after which the Dart runtime closes the
/// socket. Without recovery the transport goes permanently deaf on that
/// host candidate. These tests pin the rebind-on-death recovery in
/// TransportController.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/api/setting_engine.dart';
import 'package:webdartc/core/result.dart';
import 'package:webdartc/core/types.dart';
import 'package:webdartc/transport/transport_controller.dart';

/// First non-loopback IPv4 on this host, or null on loopback-only hosts.
Future<String?> _hostIp() async {
  final ifaces = await NetworkInterface.list(type: InternetAddressType.IPv4);
  for (final iface in ifaces) {
    for (final addr in iface.addresses) {
      if (!addr.isLoopback) return addr.address;
    }
  }
  return null;
}

void main() {
  test('transport keeps receiving after an async UDP send error', () async {
    final hostIp = await _hostIp();
    if (hostIp == null) {
      markTestSkipped('no non-loopback IPv4 interface on this host');
      return;
    }

    final tc = TransportController();
    await tc.start(
        settingEngine: const SettingEngine(bindAddresses: ['127.0.0.1']));
    addTearDown(tc.stop);
    final port = tc.bindings.first.port;

    // Provoke the async error: a loopback-bound socket sending to the
    // host IP fails with errno 1231 on Windows — reported on a later
    // event-loop tick, at which point the runtime closes the socket.
    tc.handleIceControl(Ok(ProcessResult(outputPackets: [
      OutputPacket(
        data: Uint8List.fromList(List.filled(64, 0x42)),
        remoteIp: hostIp,
        remotePort: 9,
      ),
    ])));
    // Let the error surface and the rebind complete.
    await Future<void>.delayed(const Duration(milliseconds: 500));

    // The transport must still receive on its advertised binding.
    final probe =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(probe.close);
    final payload = Uint8List.fromList(List.filled(32, 0x21));
    final before = tc.packetsReceived;
    // A few attempts paper over the (sub-ms, but real) rebind gap.
    for (var i = 0; i < 5 && tc.packetsReceived == before; i++) {
      probe.send(payload, InternetAddress.loopbackIPv4, port);
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }

    expect(tc.packetsReceived, greaterThan(before),
        reason: 'transport went deaf after the async send error '
            '(socket closed by the runtime and never rebound)');
  });

  test('stop() does not resurrect sockets', () async {
    final tc = TransportController();
    await tc.start(
        settingEngine: const SettingEngine(bindAddresses: ['127.0.0.1']));
    final port = tc.bindings.first.port;
    await tc.stop();
    // The deliberate close also fires onDone; give a would-be rebind
    // time to (incorrectly) happen, then verify the port is free.
    await Future<void>.delayed(const Duration(milliseconds: 200));
    final reuse =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, port);
    reuse.close();
  });
}
