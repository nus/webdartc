/// DTLS 1.3 endpoint library (RFC 9147 + RFC 8446).
///
/// This library hosts the two role state machines as `part` files —
/// [DtlsV13ClientStateMachine] and [DtlsV13ServerStateMachine] — plus the
/// role-neutral machinery they share:
///
///   * [DtlsV13RecordLayer] — epoch/sequence bookkeeping, traffic keys named
///     by *direction* (tx/rx) instead of client/server, plaintext + ciphertext
///     record emission, decryption, KeyUpdate key rotation, and handshake
///     fragment reassembly.
///   * [DtlsV13Endpoint] — the common endpoint base: record dispatch,
///     retransmit timers, ACK / KeyUpdate / application-data handling, and
///     SRTP keying-material export. Role subclasses keep only the handshake
///     transitions (`_handle*` / flight builders) and a small set of
///     state-predicate hooks.
library;

import 'dart:typed_data';

import '../../core/byte_io.dart';
import '../../core/state_machine.dart' as core;
import '../../core/types.dart';
import '../../crypto/csprng.dart';
import '../../crypto/ecdh.dart';
import '../../crypto/ecdsa.dart';
import '../../crypto/hmac_sha256.dart';
import '../../crypto/sha256.dart';
import '../../crypto/x25519.dart';
import '../../crypto/x509_der.dart';
import '../record.dart';
import '../srtp_profiles.dart';
import 'cipher_suite.dart';
import 'cookie.dart';
import 'handshake.dart';
import 'key_schedule.dart';
import 'record_crypto.dart';
import 'srtp_export.dart';
import 'transcript.dart';

part 'client_state_machine.dart';
part 'state_machine.dart';

/// Shared DTLS 1.3 record layer (RFC 9147 §4–5).
///
/// Keys and epochs are named by direction — `tx` is what this endpoint
/// sends with, `rx` is what it receives with — so the same code serves both
/// roles (the server's tx keys are the client's rx keys and vice versa).
final class DtlsV13RecordLayer {
  IpAddress? remoteIp;
  int? remotePort;

  /// Negotiated cipher suite; null until the ServerHello leg fixes it.
  /// Emission/decryption fall back to AES-128-GCM while unset.
  TlsV13CipherSuite? suite;

  TrafficKeys? txHandshakeKeys;
  TrafficKeys? rxHandshakeKeys;
  TrafficKeys? txApplicationKeys;
  TrafficKeys? rxApplicationKeys;

  int sendSeqEpoch0 = 0;
  int sendSeqEpoch2 = 0;
  int sendSeqEpoch3 = 0;
  int outboundMsgSeq = 0;

  /// Current application-data tx epoch (RFC 9147 §6.1). Starts at 3 once
  /// the handshake completes and increments by one each time we emit a
  /// KeyUpdate. The truncated value carried in record headers is
  /// `txAppEpoch & 0x03`.
  int txAppEpoch = 3;

  /// Current application-data rx epoch. Starts at 3 and increments by one
  /// each time we successfully process a peer KeyUpdate.
  int rxAppEpoch = 3;

  /// Record number of the last successfully decrypted inbound record,
  /// captured right before handshake dispatch so that handlers (Finished,
  /// KeyUpdate) can build an ACK referencing it without re-plumbing the
  /// decrypt result through every dispatch path (RFC 9147 §7.1).
  DtlsAckRecordNumber? lastRxRecordNumber;

  /// In-progress handshake message reassembly. Keyed by `messageSeq`. Each
  /// entry buffers the full message body until every fragment has arrived
  /// (RFC 9147 §5.5).
  final Map<int, _Reassembly> _fragmentBuffer = <int, _Reassembly>{};

  TlsV13CipherSuite get _suiteOrDefault =>
      suite ?? TlsV13CipherSuite.aes128GcmSha256;

  OutputPacket _toPacket(Uint8List data) => OutputPacket(
        data: data,
        remoteIp: remoteIp!.toCanonical(),
        remotePort: remotePort!,
      );

  /// Wrap a handshake fragment in a DTLSPlaintext (epoch 0) record.
  OutputPacket emitPlaintextHandshake(Uint8List handshakeFragment) {
    final rec = DtlsRecord(
      contentType: DtlsContentType.handshake,
      version: 0xFEFD,
      epoch: 0,
      sequenceNumber: sendSeqEpoch0++,
      fragment: handshakeFragment,
    ).encode();
    return _toPacket(rec);
  }

  /// Encrypt [handshakeFragment] under the tx handshake (epoch 2) keys.
  OutputPacket encryptHandshake(Uint8List handshakeFragment) {
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: DtlsContentType.handshake,
      content: handshakeFragment,
      epoch: 2,
      seqNum: sendSeqEpoch2++,
      keys: txHandshakeKeys!,
      cipherSuite: _suiteOrDefault,
    );
    return _toPacket(rec);
  }

  /// Encrypt [content] of [contentType] under the tx application keys at
  /// the current tx app epoch.
  OutputPacket encryptAtAppEpoch({
    required int contentType,
    required Uint8List content,
  }) {
    final rec = DtlsV13RecordCrypto.encrypt(
      contentType: contentType,
      content: content,
      epoch: txAppEpoch,
      seqNum: sendSeqEpoch3++,
      keys: txApplicationKeys!,
      cipherSuite: _suiteOrDefault,
    );
    return _toPacket(rec);
  }

  /// Decrypt a unified-header ciphertext record with either the rx
  /// handshake keys (epoch 2) or the rx application keys (current rx app
  /// epoch). Returns null — RFC 9147 §4.5.3 silent drop — when the needed
  /// keys aren't derived yet or authentication fails. On success,
  /// [lastRxRecordNumber] is updated to the decrypted record's number.
  DtlsV13DecryptResult? decryptCiphertext(
    Uint8List packet, {
    required bool useHandshakeKeys,
  }) {
    final keys = useHandshakeKeys ? rxHandshakeKeys : rxApplicationKeys;
    if (keys == null) return null;
    final epoch = useHandshakeKeys ? 2 : rxAppEpoch;
    final out = DtlsV13RecordCrypto.decrypt(
      record: packet,
      keys: keys,
      epoch: epoch,
      cipherSuite: _suiteOrDefault,
    );
    if (out == null) return null;
    lastRxRecordNumber = DtlsAckRecordNumber(epoch, out.seqNum);
    return out;
  }

  /// Rotate the tx application keys to the next generation after emitting
  /// a KeyUpdate (RFC 9147 §6.1): next-gen secret + keys, epoch bump,
  /// sequence reset.
  void rotateTxApplicationKeys() {
    final nextSecret = TlsV13KeySchedule.deriveNextTrafficSecret(
      txApplicationKeys!.trafficSecret,
    );
    txApplicationKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: nextSecret,
      keyLength: _suiteOrDefault.keyLength,
    );
    txAppEpoch += 1;
    sendSeqEpoch3 = 0;
  }

  /// Rotate the rx application keys after processing a peer KeyUpdate.
  void rotateRxApplicationKeys() {
    final nextSecret = TlsV13KeySchedule.deriveNextTrafficSecret(
      rxApplicationKeys!.trafficSecret,
    );
    rxApplicationKeys = TlsV13KeySchedule.deriveTrafficKeys(
      trafficSecret: nextSecret,
      keyLength: _suiteOrDefault.keyLength,
    );
    rxAppEpoch += 1;
  }

  /// Stash a fragment's body in the reassembly buffer. Returns the fully
  /// reassembled body once every byte has been observed, otherwise null.
  /// Out-of-order arrival, duplicate fragments, and overlapping fragments
  /// are tolerated; the first copy of a given byte wins.
  Uint8List? accumulateFragment(DtlsHandshakeHeader hs) {
    final buf = _fragmentBuffer.putIfAbsent(
      hs.messageSeq,
      () => _Reassembly(hs.length),
    );
    if (buf.totalLength != hs.length) {
      // Inconsistent total length across fragments — can't reassemble.
      return null;
    }
    final end = hs.fragmentOffset + hs.body.length;
    if (end > buf.totalLength) return null;
    for (var i = 0; i < hs.body.length; i++) {
      if (!buf.received[hs.fragmentOffset + i]) {
        buf.received[hs.fragmentOffset + i] = true;
        buf.bodyOut[hs.fragmentOffset + i] = hs.body[i];
        buf.bytesGot++;
      }
    }
    if (buf.bytesGot < buf.totalLength) return null;
    _fragmentBuffer.remove(hs.messageSeq);
    return Uint8List.fromList(buf.bodyOut);
  }
}

/// Reassembly state for a single in-flight handshake message.
final class _Reassembly {
  final int totalLength;
  final List<int> bodyOut;
  final List<bool> received;
  int bytesGot = 0;

  _Reassembly(this.totalLength)
      : bodyOut = List<int>.filled(totalLength, 0),
        received = List<bool>.filled(totalLength, false);
}

/// Build the DTLS-form bytes a fully-reassembled handshake message would
/// have if it had been sent as a single fragment — `type(1) + length(3)
/// + msg_seq(2) + frag_offset=0(3) + frag_length=length(3) + body`. This
/// is what the transcript hash and downstream handlers expect.
Uint8List _buildSingleFragmentView(
  int msgType,
  int messageSeq,
  Uint8List body,
) {
  final out = Uint8List(12 + body.length);
  out[0] = msgType;
  writeU24(out, 1, body.length);
  writeU16(out, 4, messageSeq);
  writeU24(out, 6, 0); // fragment_offset
  writeU24(out, 9, body.length); // fragment_length
  out.setRange(12, out.length, body);
  return out;
}

/// Common DTLS 1.3 endpoint behaviour shared by [DtlsV13ClientStateMachine]
/// and [DtlsV13ServerStateMachine]: record dispatch, flight retransmission,
/// ACK / KeyUpdate / application-data processing, and SRTP export. Role
/// subclasses implement the `_dispatchHandshakeMessage` switch plus a small
/// set of state-predicate hooks.
abstract base class DtlsV13Endpoint implements core.ProtocolStateMachine {
  DtlsV13Endpoint({required this.localCert});

  /// This endpoint's X.509 certificate + signing key. The DER bytes are
  /// sent in a Certificate message; the private key signs the
  /// CertificateVerify content.
  final EcdsaCertificate localCert;

  /// Expected SHA-256 fingerprint of the *peer's* certificate, formatted
  /// as colon-separated uppercase hex (matching the SDP `a=fingerprint`
  /// convention used by [EcdsaCertificate.sha256Fingerprint]). When
  /// non-null, the peer's actual cert fingerprint is compared after
  /// parsing its Certificate; mismatch fails the handshake with a
  /// `CryptoError`. When null, no check is performed.
  String? expectedRemoteFingerprint;

  // ─── Callbacks ────────────────────────────────────────────────────────

  /// Fired exactly once when the handshake transitions to CONNECTED.
  /// The argument is the SRTP keying material exported from
  /// `exporter_master_secret` per RFC 5764 §4.2. Its length and layout
  /// depend on the negotiated SRTP profile (see [selectedSrtpProfileId]):
  ///   * SRTP_AES128_CM_HMAC_SHA1_80 / _32 → 60 bytes
  ///     (16+16 master keys, 14+14 master salts).
  ///   * SRTP_AEAD_AES_128_GCM             → 56 bytes
  ///     (16+16 master keys, 12+12 master salts) per RFC 7714 §12.
  ///   * SRTP_AEAD_AES_256_GCM             → 88 bytes
  ///     (32+32 master keys, 12+12 master salts) per RFC 7714 §12.
  void Function(Uint8List srtpKeyingMaterial)? onConnected;

  /// Fired for every successfully decrypted application_data record.
  void Function(Uint8List data)? onApplicationData;

  // ─── Public state observables ────────────────────────────────────────

  /// The negotiated cipher suite, or null until negotiation.
  TlsV13CipherSuite? get cipherSuite => _records.suite;

  /// `exporter_master_secret` available after handshake completes
  /// (RFC 8446 §7.5).
  Uint8List? get exporterMasterSecret => _exporterMasterSecret;

  /// SRTP protection profile (RFC 5764) negotiated via the use_srtp
  /// extension, or null when none was negotiated.
  int? get selectedSrtpProfileId => _selectedSrtpProfile;

  // ─── Shared internal state ────────────────────────────────────────────

  final DtlsV13RecordLayer _records = DtlsV13RecordLayer();
  final DtlsV13Transcript _transcript = DtlsV13Transcript();

  TlsV13CipherSuite? get _suite => _records.suite;

  /// Negotiated key-exchange group for this session — either
  /// `secp256r1` (0x0017) or `x25519` (0x001D).
  int? _selectedGroup;

  /// secp256r1 ephemeral private key, when in play for this session.
  EcdhKeyPair? _ecdhKeyPair;

  /// x25519 ephemeral private key, when in play for this session.
  X25519KeyPair? _x25519KeyPair;

  /// Selected SRTP profile from RFC 5764 use_srtp negotiation, e.g. 0x0001
  /// for `SRTP_AES128_CM_HMAC_SHA1_80` or 0x0007 for `SRTP_AEAD_AES_128_GCM`.
  int? _selectedSrtpProfile;

  /// 65-byte uncompressed P-256 pubkey extracted from the peer's
  /// Certificate message. Used to verify its CertificateVerify.
  Uint8List? _peerCertPubKey;

  Uint8List? _earlySecret;
  Uint8List? _handshakeSecret;
  Uint8List? _masterSecret;
  Uint8List? _exporterMasterSecret;

  /// True after we've received a KeyUpdate(update_requested) from the
  /// peer; we owe them a reciprocal KeyUpdate before our next
  /// application_data record (RFC 8446 §4.6.3). Cleared on emission.
  bool _peerRequestedKeyUpdate = false;

  /// The most recently emitted flight, kept so [handleTimeout] can re-send
  /// it when the peer doesn't reply in time (RFC 9147 §5.7).
  List<OutputPacket>? _lastFlight;

  /// Number of retransmissions performed for the current outbound flight
  /// (RFC 9147 §5.7). Reset whenever a new flight is sent. Each
  /// handleTimeout fire bumps this and reschedules the next timer with
  /// exponential backoff.
  int _handshakeRetransmitCount = 0;

  /// RFC 9147 §5.7 caps the total retransmission window at "implementation
  /// defined". 6 retries with 1s base ⇒ 1+2+4+8+16+32 = 63s ceiling, which
  /// matches the legacy v1.2 path and is well under WebRTC ICE-consent
  /// freshness.
  static const int _maxHandshakeRetransmits = 6;
  static const int _initialHandshakeRetransmitMs = 1000;

  // ─── Role hooks ───────────────────────────────────────────────────────

  /// Whether the handshake has completed (role state == connected).
  bool get _isConnected;

  /// Transition the role state to failed.
  void _markFailed();

  /// Whether inbound ciphertext records should be decrypted with the rx
  /// *handshake* keys (epoch 2) rather than the rx application keys.
  bool get _rxUsesHandshakeKeys;

  /// Whether the endpoint is in a state where the last flight should be
  /// retransmitted on timer expiry.
  bool get _retransmitPending;

  /// Error returned when the retransmit budget is exhausted.
  core.ProtocolError get _retransmitLimitError;

  /// Role-specific handshake message dispatch. Receives the reassembled
  /// message body plus the single-fragment DTLS-form bytes ([fullDtls])
  /// used for transcript hashing.
  core.Result<ProcessResult, core.ProtocolError> _dispatchHandshakeMessage(
    int msgType,
    Uint8List body,
    Uint8List fullDtls,
  );

  // ─── ProtocolStateMachine ─────────────────────────────────────────────

  @override
  core.Result<ProcessResult, core.ProtocolError> processInput(
    Uint8List packet, {
    required IpAddress remoteIp,
    required int remotePort,
  }) {
    _records.remoteIp = remoteIp;
    _records.remotePort = remotePort;
    if (packet.isEmpty) return const core.Ok(ProcessResult.empty);

    // Top three bits `001` mark a DTLS 1.3 ciphertext (unified header).
    // Anything else is treated as a legacy DTLSPlaintext record (used for
    // epoch 0 ClientHello / ServerHello).
    if ((packet[0] & 0xE0) == 0x20) {
      return _processCiphertextRecord(packet);
    }
    return _processPlaintextRecord(packet);
  }

  @override
  core.Result<ProcessResult, core.ProtocolError> handleTimeout(
    TimerToken token,
  ) {
    if (token is! DtlsRetransmitToken) {
      return const core.Ok(ProcessResult.empty);
    }
    // Only retransmit while we are still waiting on the peer to advance
    // the handshake. Otherwise drop the timer silently — the next
    // _armFlightRetransmit call from a real event will replace it.
    if (!_retransmitPending) return const core.Ok(ProcessResult.empty);
    final flight = _lastFlight;
    if (flight == null) return const core.Ok(ProcessResult.empty);
    if (_handshakeRetransmitCount >= _maxHandshakeRetransmits) {
      _markFailed();
      return core.Err(_retransmitLimitError);
    }
    _handshakeRetransmitCount += 1;
    return core.Ok(ProcessResult(
      outputPackets: List.of(flight),
      nextTimeout: _nextHandshakeRetransmitTimeout(),
    ));
  }

  /// Record [flight] as the retransmittable last flight, reset the
  /// retransmit budget, and return the timeout that arms its timer.
  Timeout _armFlightRetransmit(List<OutputPacket> flight) {
    _lastFlight = List.of(flight);
    _handshakeRetransmitCount = 0;
    return _nextHandshakeRetransmitTimeout();
  }

  /// Compute the next exponential-backoff timeout for the active flight
  /// (RFC 9147 §5.7 / RFC 6347 §4.2.4.1). Base 1s, doubling per attempt,
  /// capped at 60s.
  Timeout _nextHandshakeRetransmitTimeout() {
    final delayMs = (_initialHandshakeRetransmitMs *
            (1 << _handshakeRetransmitCount))
        .clamp(0, 60000);
    return Timeout(
      at: DateTime.now().add(Duration(milliseconds: delayMs)),
      token: DtlsRetransmitToken(0),
    );
  }

  // ─── Record dispatch ──────────────────────────────────────────────────

  core.Result<ProcessResult, core.ProtocolError> _processPlaintextRecord(
    Uint8List packet,
  ) {
    final rec = DtlsRecord.parse(packet, 0);
    if (rec == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad plaintext record'));
    }
    if (rec.epoch != 0) {
      // Encrypted records must come through the unified-header path.
      return const core.Ok(ProcessResult.empty);
    }
    if (rec.contentType != DtlsContentType.handshake) {
      return const core.Ok(ProcessResult.empty);
    }
    return _processHandshakeFragments(rec.fragment);
  }

  core.Result<ProcessResult, core.ProtocolError> _processCiphertextRecord(
    Uint8List packet,
  ) {
    final out = _records.decryptCiphertext(
      packet,
      useHandshakeKeys: _rxUsesHandshakeKeys,
    );
    if (out == null) {
      // RFC 9147 §4.5.3: silently drop unauthenticatable records.
      return const core.Ok(ProcessResult.empty);
    }
    switch (out.contentType) {
      case DtlsContentType.handshake:
        return _processHandshakeFragments(out.content);
      case DtlsContentType.applicationData:
        if (_isConnected) {
          onApplicationData?.call(out.content);
        }
        return const core.Ok(ProcessResult.empty);
      case DtlsContentType.ack:
        // RFC 9147 §7: parse and discard. We do not yet maintain a
        // per-record retransmit queue to clear, so received ACKs are
        // informational only. Malformed bodies are silently dropped per
        // §4.5.3 (unauthenticatable / unexpected records).
        parseAckRecord(out.content);
        return const core.Ok(ProcessResult.empty);
      case DtlsContentType.alert:
        _markFailed();
        return const core.Ok(ProcessResult.empty);
      default:
        return const core.Ok(ProcessResult.empty);
    }
  }

  // ─── Handshake message dispatch ───────────────────────────────────────

  /// Walk a buffer that may carry one or more concatenated DTLS handshake
  /// records. WebRTC peers (notably Firefox) bundle response flights —
  /// e.g. `Certificate || CertificateVerify || Finished` — into a single
  /// ciphertext record, so we keep dispatching successive fragments until
  /// the buffer is exhausted.
  core.Result<ProcessResult, core.ProtocolError> _processHandshakeFragments(
    Uint8List buf,
  ) {
    final outputs = <OutputPacket>[];
    Timeout? lastTimeout;
    var offset = 0;
    while (offset < buf.length) {
      if (buf.length - offset < 12) {
        return core.Err(
          const core.ParseError('DTLS 1.3: short handshake header'),
        );
      }
      final fragLen = readU24(buf, offset + 9);
      final total = 12 + fragLen;
      if (offset + total > buf.length) {
        return core.Err(
          const core.ParseError('DTLS 1.3: truncated handshake fragment'),
        );
      }
      final slice = Uint8List.sublistView(buf, offset, offset + total);
      final r = _processHandshakeFragment(slice);
      if (r.isErr) return r;
      outputs.addAll(r.value.outputPackets);
      // Last non-null nextTimeout wins; flight-emitting handlers set this
      // so the upper layer can schedule a retransmit timer (RFC 9147 §5.7).
      if (r.value.nextTimeout != null) lastTimeout = r.value.nextTimeout;
      offset += total;
    }
    return core.Ok(
      ProcessResult(outputPackets: outputs, nextTimeout: lastTimeout),
    );
  }

  /// Parse one handshake fragment, reassemble if fragmented (RFC 9147
  /// §5.5), and hand the completed message to the role's dispatch switch.
  core.Result<ProcessResult, core.ProtocolError> _processHandshakeFragment(
    Uint8List fragment,
  ) {
    final hs = DtlsHandshakeHeader.parse(fragment);
    if (hs == null) {
      return core.Err(const core.ParseError('DTLS 1.3: bad handshake header'));
    }

    // When a record carries the entire message in one fragment we use its
    // bytes directly; otherwise we accumulate fragments by messageSeq until
    // the whole body is in hand, then synthesize a single-fragment view.
    final int msgType;
    final Uint8List body;
    final Uint8List fullDtls;
    if (hs.fragmentOffset == 0 && hs.fragmentLength == hs.length) {
      msgType = hs.msgType;
      body = hs.body;
      fullDtls = fragment.sublist(0, 12 + hs.body.length);
    } else {
      final completed = _records.accumulateFragment(hs);
      if (completed == null) {
        return const core.Ok(ProcessResult.empty);
      }
      msgType = hs.msgType;
      body = completed;
      fullDtls = _buildSingleFragmentView(hs.msgType, hs.messageSeq, completed);
    }

    return _dispatchHandshakeMessage(msgType, body, fullDtls);
  }

  // ─── KeyUpdate / ACK ──────────────────────────────────────────────────

  /// Handle a peer KeyUpdate (RFC 8446 §4.6.3 / RFC 9147 §6.1):
  /// rotate the rx application keys to the next generation, bump the rx
  /// app epoch, ACK the KeyUpdate record (RFC 9147 §7 — KeyUpdate is
  /// non-eliciting, so the only signal back is an ACK), and (if the peer
  /// set `update_requested`) record that we owe a reciprocal KeyUpdate
  /// before our next application_data.
  core.Result<ProcessResult, core.ProtocolError> _handleKeyUpdate(
    Uint8List body,
  ) {
    final req = parseKeyUpdateBody(body);
    if (req == null) {
      return core.Err(
        const core.ParseError('DTLS 1.3: malformed KeyUpdate body'),
      );
    }
    final ackRn = _records.lastRxRecordNumber!;
    _records.rotateRxApplicationKeys();
    if (req == KeyUpdateRequest.requested) {
      _peerRequestedKeyUpdate = true;
    }
    final ackPkt = _emitAck([ackRn]);
    return core.Ok(ProcessResult(outputPackets: [ackPkt]));
  }

  /// Encrypt and emit an ACK record (RFC 9147 §7) at the current tx app
  /// epoch using our application keys. Caller supplies the (epoch, seq)
  /// pairs to acknowledge.
  OutputPacket _emitAck(List<DtlsAckRecordNumber> records) =>
      _records.encryptAtAppEpoch(
        contentType: DtlsContentType.ack,
        content: buildAckRecord(records),
      );

  // ─── Public application-data API ──────────────────────────────────────

  /// Encrypt [data] as an application_data record. Returns an Err if the
  /// handshake hasn't reached CONNECTED yet — callers can still use a
  /// uniform success / failure flow.
  core.Result<ProcessResult, core.ProtocolError> sendApplicationData(
    Uint8List data,
  ) {
    if (!_isConnected) {
      return core.Err(
        const core.StateError('DTLS 1.3: sendApplicationData before CONNECTED'),
      );
    }
    final outputs = <OutputPacket>[];
    if (_peerRequestedKeyUpdate) {
      outputs.add(_emitKeyUpdate(KeyUpdateRequest.notRequested));
    }
    outputs.add(_records.encryptAtAppEpoch(
      contentType: DtlsContentType.applicationData,
      content: data,
    ));
    return core.Ok(ProcessResult(outputPackets: outputs));
  }

  /// Trigger a post-handshake `KeyUpdate` (RFC 8446 §4.6.3 / RFC 9147
  /// §6.1). Emits the message under the current tx app keys, then rotates
  /// our own application-data sender to the next-generation keys / epoch.
  ///
  /// [requestPeerUpdate] sets the `KeyUpdateRequest` field to
  /// `update_requested(1)`; the peer must reciprocate before its next
  /// application_data record.
  core.Result<ProcessResult, core.ProtocolError> requestKeyUpdate({
    bool requestPeerUpdate = false,
  }) {
    if (!_isConnected) {
      return core.Err(
        const core.StateError('DTLS 1.3: requestKeyUpdate before CONNECTED'),
      );
    }
    final pkt = _emitKeyUpdate(
      requestPeerUpdate
          ? KeyUpdateRequest.requested
          : KeyUpdateRequest.notRequested,
    );
    return core.Ok(ProcessResult(outputPackets: [pkt]));
  }

  /// Build, encrypt, and emit a KeyUpdate handshake message under the
  /// current tx app keys. After the record is on the wire the next-gen
  /// secret + keys are derived and tx epoch / sequence are bumped per
  /// RFC 9147 §6.1.
  OutputPacket _emitKeyUpdate(int request) {
    final fragment = wrapHandshake(
      msgType: TlsV13HandshakeType.keyUpdate,
      msgSeq: _records.outboundMsgSeq++,
      body: buildKeyUpdateBody(request),
    );
    final pkt = _records.encryptAtAppEpoch(
      contentType: DtlsContentType.handshake,
      content: fragment,
    );
    // Rotate our sender to the next generation. The KeyUpdate itself was
    // sent under the old keys; everything after this point uses the new.
    _records.rotateTxApplicationKeys();
    _peerRequestedKeyUpdate = false;
    return pkt;
  }

  // ─── Shared emit / verify helpers ─────────────────────────────────────

  /// Wrap a handshake fragment in a DTLSPlaintext (epoch 0) record.
  OutputPacket _emitPlaintextHandshake(Uint8List handshakeFragment) =>
      _records.emitPlaintextHandshake(handshakeFragment);

  /// Constant-time comparison used for Finished verify_data. Lengths must
  /// already be equal.
  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Fire [onConnected] with the SRTP keying material exported from
  /// `exporter_master_secret`, sized to the negotiated SRTP profile
  /// (RFC 7714 §12). When use_srtp wasn't negotiated we default to the
  /// legacy 60-byte AES-CM length so existing tests / non-SRTP callers
  /// keep working.
  void _fireOnConnected() {
    final cb = onConnected;
    if (cb == null) return;
    final exportLen = _selectedSrtpProfile != null
        ? SrtpProfileNegotiation.exportLength(_selectedSrtpProfile!)
        : DtlsV13SrtpExport.srtpAes128CmHmacSha180Length;
    cb(DtlsV13SrtpExport.export(
      exporterMasterSecret: _exporterMasterSecret!,
      length: exportLen,
    ));
  }
}
