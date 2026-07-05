part of 'transport_controller.dart';

/// Routes each inbound datagram to its protocol: TURN allocations first
/// (server-addressed traffic), then STUN/ICE, DTLS records, or SRTP/SRTCP
/// by first-byte range.
final class PacketDemuxer {
  final TransportController _tc;

  PacketDemuxer(this._tc);

  void dispatch(Uint8List data, int arrivalUs, IpAddress remoteIp,
      int remotePort, IpAddress localIp) {
    if (data.isEmpty) return;
    final firstByte = data[0];

    // Allocation lookup gated on isNotEmpty so the common no-TURN flow
    // stays a single Map.isEmpty check per datagram.
    if (_tc._allocations.isNotEmpty) {
      final allocation = _tc._allocations[(remoteIp, remotePort)];
      if (allocation != null) {
        final result = allocation.processInput(
          data,
          remoteIp: remoteIp,
          remotePort: remotePort,
        );
        if (result.isOk) {
          _tc._sendOutputPackets(result.value.outputPackets);
          _tc._timers.schedule(
              result.value.nextTimeout, 'turn-$remoteIp:$remotePort');
        }
        return;
      }
    }

    if (StunParser.isStun(data)) {
      _processIce(data, remoteIp, remotePort, localIp);
    } else if (firstByte >= 20 && firstByte <= 63) {
      // DTLS record layer. Remember which local socket received it so
      // outgoing DTLS records (which don't carry a localIp in their
      // OutputPackets) reply on the same interface — important on
      // Windows where cross-interface UDP sends can fail.
      _tc._pool._lastInboundLocalIp = localIp;
      _processDtls(data, remoteIp, remotePort);
    } else if (firstByte >= 128 && firstByte <= 191) {
      // RTP or RTCP
      _processSrtp(data, arrivalUs);
    }
    // Else: unknown — discard
  }

  void _processIce(Uint8List data, IpAddress remoteIp, int remotePort,
      IpAddress localIp) {
    final ice = _tc._ice;
    if (ice == null) return;
    final result = ice.processInput(data,
        remoteIp: remoteIp, remotePort: remotePort, localIp: localIp);
    if (result.isOk) {
      _tc._sendOutputPackets(result.value.outputPackets);
      _tc._timers.schedule(result.value.nextTimeout, 'ice-check');
    }
  }

  void _processDtls(Uint8List data, IpAddress remoteIp, int remotePort) {
    final dtls = _tc._dtls;
    if (dtls == null) return;
    final result = dtls.processInput(data,
        remoteIp: remoteIp, remotePort: remotePort);
    if (result.isOk) {
      _tc._sendOutputPackets(result.value.outputPackets);
      _tc._timers.schedule(result.value.nextTimeout, 'dtls-retransmit');
    }
  }

  void _processSrtp(Uint8List data, int arrivalUs) {
    final srtp = _tc._srtp;
    if (srtp == null) return;

    if (RtpParser.isRtcp(data)) {
      final decResult = srtp.decryptRtcp(data);
      if (decResult.isOk) {
        _tc.onRtcp?.call(decResult.value);
      } else if (TransportController._debug) {
        webdartcLog('[transport] SRTCP decrypt failed: ${decResult.error} len=${data.length}');
      }
    } else {
      final decResult = srtp.decryptRtp(data);
      if (decResult.isOk) {
        _tc.onRtp?.call(decResult.value, arrivalUs);
      } else if (TransportController._debug) {
        webdartcLog('[transport] SRTP decrypt failed: ${decResult.error} len=${data.length}'
            ' b0=0x${data[0].toRadixString(16)}');
      }
    }
  }
}
