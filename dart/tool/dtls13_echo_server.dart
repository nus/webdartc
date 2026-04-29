// Stand-alone DTLS 1.2 / DTLS 1.3 UDP echo server for ad-hoc interop
// testing. Binds a UDP socket, routes datagrams through
// [DtlsServerDispatcher], and echoes any decrypted application_data
// records back to the peer.
//
// Manual interop checks (run from a separate shell):
//
//   * OpenSSL DTLS 1.3 client (OpenSSL 3.2+):
//       openssl s_client -dtls1_3 -connect 127.0.0.1:5000
//
//   * OpenSSL DTLS 1.2 client (always available):
//       openssl s_client -dtls1_2 -connect 127.0.0.1:5000
//
//   * NSS tstclnt -t (DTLS 1.3) is also a useful reference.
//
// Server picks v1.2 vs v1.3 automatically from the ClientHello's
// `supported_versions` extension. Press Ctrl-C to terminate.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:webdartc/core/state_machine.dart';
import 'package:webdartc/crypto/ecdsa.dart';
import 'package:webdartc/dtls/dispatcher.dart';

void usage() {
  stderr.writeln('Usage: dart run tool/dtls13_echo_server.dart [--port PORT]');
  exit(2);
}

Future<void> main(List<String> args) async {
  var port = 5000;
  var bindAddr = InternetAddress.anyIPv4;
  for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--port':
        if (i + 1 >= args.length) usage();
        port = int.parse(args[++i]);
      case '--loopback':
        bindAddr = InternetAddress.loopbackIPv4;
      case '--help':
      case '-h':
        usage();
      default:
        stderr.writeln('Unknown argument: ${args[i]}');
        usage();
    }
  }

  final socket = await RawDatagramSocket.bind(bindAddr, port);
  stderr.writeln(
    '[server] listening on ${socket.address.address}:${socket.port}',
  );

  // Long-lived self-signed certificate reused across peers.
  final cert = EcdsaCertificate.selfSigned();

  // One dispatcher per peer (keyed by ip:port). DTLS doesn't multiplex
  // sessions on a single 4-tuple, so each new peer gets a fresh inner
  // state machine via a brand-new dispatcher.
  final sessions = <String, _Session>{};

  socket.listen((event) {
    if (event != RawSocketEvent.read) return;
    final dg = socket.receive();
    if (dg == null) return;
    final remoteIp = dg.address.address;
    final remotePort = dg.port;
    final peerKey = '$remoteIp:$remotePort';

    var session = sessions[peerKey];
    if (session == null) {
      session = _Session(
        socket: socket,
        cert: cert,
        remoteIp: remoteIp,
        remotePort: remotePort,
      );
      sessions[peerKey] = session;
      stderr.writeln('[server] new peer $peerKey');
    }
    session.deliver(dg.data);
  });

  // Clean up on Ctrl-C.
  void shutdown() {
    stderr.writeln('[server] shutting down');
    socket.close();
    exit(0);
  }

  unawaited(ProcessSignal.sigint.watch().first.then((_) => shutdown()));
  if (!Platform.isWindows) {
    unawaited(ProcessSignal.sigterm.watch().first.then((_) => shutdown()));
  }
}

class _Session {
  final RawDatagramSocket socket;
  final String remoteIp;
  final int remotePort;
  final DtlsServerDispatcher dispatcher;

  _Session({
    required this.socket,
    required EcdsaCertificate cert,
    required this.remoteIp,
    required this.remotePort,
  }) : dispatcher = DtlsServerDispatcher(localCert: cert) {
    dispatcher.onConnected = (km) {
      final ver = dispatcher.isV13 == true ? 'DTLS 1.3' : 'DTLS 1.2';
      stderr.writeln(
        '[server] $remoteIp:$remotePort connected ($ver, '
        'SRTP keying material ${km.length} bytes)',
      );
    };
    dispatcher.onApplicationData = (data) {
      stderr.writeln(
        '[server] $remoteIp:$remotePort recv ${data.length}B: '
        '${_summarize(data)}',
      );
      // Echo back.
      final sent = dispatcher.sendApplicationData(data);
      sent.fold(
        ok: (result) {
          for (final pkt in result.outputPackets) {
            _sendPacket(pkt);
          }
        },
        err: (e) =>
            stderr.writeln('[server] echo failed: ${e.message}'),
      );
    };
  }

  void deliver(Uint8List packet) {
    stderr.writeln(
      '[server] $remoteIp:$remotePort recv ${packet.length}B: '
      '${_hex(packet, max: 1500)}',
    );
    final r = dispatcher.processInput(
      packet,
      remoteIp: remoteIp,
      remotePort: remotePort,
    );
    r.fold(
      ok: (result) {
        for (var i = 0; i < result.outputPackets.length; i++) {
          final pkt = result.outputPackets[i];
          stderr.writeln(
            '[server] $remoteIp:$remotePort emit[$i] ${pkt.data.length}B: '
            '${_hex(pkt.data, max: 64)}',
          );
          _sendPacket(pkt);
        }
        if (result.outputPackets.isEmpty) {
          stderr.writeln(
            '[server] $remoteIp:$remotePort no output (state: '
            'isV13=${dispatcher.isV13})',
          );
        }
      },
      err: (e) =>
          stderr.writeln('[server] $remoteIp:$remotePort error: ${e.message}'),
    );
  }

  void _sendPacket(OutputPacket pkt) {
    socket.send(pkt.data, InternetAddress(pkt.remoteIp), pkt.remotePort);
  }
}

String _hex(Uint8List data, {int max = 64}) {
  final n = data.length < max ? data.length : max;
  final buf = StringBuffer();
  for (var i = 0; i < n; i++) {
    if (i > 0) buf.write(' ');
    buf.write(data[i].toRadixString(16).padLeft(2, '0'));
  }
  if (data.length > n) buf.write(' …');
  return buf.toString();
}

String _summarize(Uint8List data) {
  // Print printable ASCII verbatim, otherwise hex.
  final buf = StringBuffer();
  var allPrintable = true;
  for (final b in data) {
    if (b < 0x20 || b > 0x7E) {
      allPrintable = false;
      break;
    }
  }
  if (allPrintable) {
    buf.write('"');
    for (final b in data) {
      buf.writeCharCode(b);
    }
    buf.write('"');
  } else {
    final n = data.length < 32 ? data.length : 32;
    for (var i = 0; i < n; i++) {
      if (i > 0) buf.write(' ');
      buf.write(data[i].toRadixString(16).padLeft(2, '0'));
    }
    if (data.length > n) buf.write(' …');
  }
  return buf.toString();
}
