import 'dart:typed_data';

import '../core/state_machine.dart';
import '../crypto/ecdsa.dart';
import 'record.dart';
import 'state_machine.dart' as v12;
import 'v13/handshake.dart' as v13;
import 'v13/state_machine.dart' as v13;

/// Server-side DTLS version dispatcher.
///
/// Inspects the first incoming UDP datagram (which must be a ClientHello),
/// looks at its `supported_versions` extension, and routes the rest of the
/// session to either the legacy DTLS 1.2 [v12.DtlsStateMachine] or the new
/// DTLS 1.3 [v13.DtlsV13ServerStateMachine].
///
/// All subsequent [processInput] / [handleTimeout] calls are forwarded
/// verbatim to the chosen inner state machine. Callbacks are wired through
/// from the inner SM so callers see one [onConnected] / [onApplicationData]
/// regardless of negotiated version.
///
/// The dispatcher does not itself implement protocol logic — it is a thin
/// routing layer that lets a single transport endpoint accept connections
/// from clients that speak either DTLS 1.2 or DTLS 1.3.
final class DtlsServerDispatcher implements ProtocolStateMachine {
  /// Server-side certificate used by whichever inner SM is selected.
  final EcdsaCertificate localCert;

  /// Fires when the inner SM transitions to its CONNECTED state. The
  /// argument is the 60-byte SRTP keying material exported per
  /// RFC 5764 §4.2.
  void Function(Uint8List srtpKeyingMaterial)? onConnected;

  /// Fires for every successfully decrypted application_data record.
  void Function(Uint8List data)? onApplicationData;

  ProtocolStateMachine? _inner;
  bool? _isV13;

  DtlsServerDispatcher({required this.localCert});

  /// Whether the dispatcher has selected the DTLS 1.3 path. Returns
  /// `null` until the first ClientHello has been routed.
  bool? get isV13 => _isV13;

  /// The inner state machine if one has been selected, otherwise `null`.
  /// Exposed primarily so test code can introspect the negotiated state.
  ProtocolStateMachine? get inner => _inner;

  @override
  Result<ProcessResult, ProtocolError> processInput(
    Uint8List packet, {
    required String remoteIp,
    required int remotePort,
  }) {
    final inner = _inner;
    if (inner != null) {
      return inner.processInput(packet,
          remoteIp: remoteIp, remotePort: remotePort);
    }
    final selection = _selectVariant(packet);
    if (selection == null) {
      return Err(const ParseError(
        'DTLS dispatch: first packet must be a parseable ClientHello',
      ));
    }
    _isV13 = selection;
    _inner = _createInner(selection);
    return _inner!.processInput(packet,
        remoteIp: remoteIp, remotePort: remotePort);
  }

  @override
  Result<ProcessResult, ProtocolError> handleTimeout(TimerToken token) {
    final inner = _inner;
    if (inner == null) return const Ok(ProcessResult.empty);
    return inner.handleTimeout(token);
  }

  /// Encrypt [data] as a DTLS application_data record using whichever
  /// inner state machine has been selected. Returns an [Err] if the
  /// dispatcher hasn't yet seen a ClientHello, or if the inner SM's
  /// own send API rejects the call (e.g., before CONNECTED).
  Result<ProcessResult, ProtocolError> sendApplicationData(Uint8List data) {
    final inner = _inner;
    if (inner is v13.DtlsV13ServerStateMachine) {
      return inner.sendApplicationData(data);
    }
    if (inner is v12.DtlsStateMachine) {
      return inner.sendApplicationData(data);
    }
    return Err(
      const StateError('DTLS dispatch: send before any ClientHello'),
    );
  }

  /// Inspect [packet] and decide whether the client is offering DTLS 1.3.
  ///
  /// Returns `true` for DTLS 1.3, `false` for DTLS 1.2, or `null` when
  /// the packet is not a parseable ClientHello (the caller treats this
  /// as a routing failure).
  bool? _selectVariant(Uint8List packet) {
    final rec = DtlsRecord.parse(packet, 0);
    if (rec == null) return null;
    if (rec.epoch != 0) return null;
    if (rec.contentType != DtlsContentType.handshake) return null;
    final hs = DtlsHandshakeHeader.parse(rec.fragment);
    if (hs == null) return null;
    if (hs.msgType != v13.TlsV13HandshakeType.clientHello) return null;
    final ch = v13.parseClientHello(hs.body);
    if (ch == null) return null;
    final sv = ch.extensionByType(v13.TlsV13ExtensionType.supportedVersions);
    if (sv == null) {
      // No supported_versions ⇒ pre-TLS 1.3 client, route to DTLS 1.2.
      return false;
    }
    final versions = v13.parseClientHelloSupportedVersionsExtData(sv.data);
    if (versions == null) return false;
    return versions.contains(v13.dtls13Version);
  }

  ProtocolStateMachine _createInner(bool v13Selected) {
    if (v13Selected) {
      final sm = v13.DtlsV13ServerStateMachine(localCert: localCert);
      sm.onConnected = (km) => onConnected?.call(km);
      sm.onApplicationData = (data) => onApplicationData?.call(data);
      return sm;
    }
    final sm = v12.DtlsStateMachine(
      role: v12.DtlsRole.server,
      localCert: localCert,
    );
    sm.onConnected = (km) => onConnected?.call(km);
    sm.onApplicationData = (data) => onApplicationData?.call(data);
    return sm;
  }
}
