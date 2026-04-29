import 'dart:typed_data';

import '../core/result.dart';
import '../core/state_machine.dart' show CryptoError;
import '../crypto/aes_cm.dart';
import '../crypto/aes_gcm.dart';
import '../crypto/hmac_sha1.dart';

/// SRTP cipher profiles (RFC 3711 + RFC 7714).
enum SrtpProfile {
  /// AES-128-CM-HMAC-SHA1-80 (RFC 3711)
  aesCm128HmacSha1_80,

  /// AES-128-CM-HMAC-SHA1-32 (RFC 3711)
  aesCm128HmacSha1_32,

  /// AES-128-GCM (RFC 7714)
  aesGcm128,

  /// AES-256-GCM (RFC 7714)
  aesGcm256,
}

/// ROC (Rollover Counter) tracker for SRTP index computation (RFC 3711 §3.3.1).
final class _RocTracker {
  int _roc = 0;
  int _sL = 0; // highest seq number seen
  // Replay protection (RFC 3711 §3.3.2): sliding window of 64 packets
  static const int _replayWindowSize = 64;
  int _replayWindowBase = 0; // index of the lowest bit in the window
  int _replayBitmask = 0; // bitmask of received indices relative to base

  // Index = 2^16 * ROC + SEQ
  int indexFor(int seq) {
    final v = _guessRoc(seq);
    return (1 << 16) * v + seq;
  }

  /// Check if a packet index has been seen before (replay attack).
  bool isReplay(int index) {
    if (index < _replayWindowBase) return true; // too old
    final offset = index - _replayWindowBase;
    if (offset >= _replayWindowSize) return false; // ahead of window, new
    return (_replayBitmask & (1 << offset)) != 0;
  }

  void update(int seq) {
    final v = _guessRoc(seq);
    if (v == _roc + 1) _roc = v;
    _sL = seq;
  }

  /// Mark a packet index as received in the replay window.
  void markReceived(int index) {
    if (index >= _replayWindowBase + _replayWindowSize) {
      // Advance the window
      final shift = index - _replayWindowBase - _replayWindowSize + 1;
      _replayBitmask >>>= shift;
      _replayWindowBase += shift;
    }
    final offset = index - _replayWindowBase;
    if (offset >= 0 && offset < _replayWindowSize) {
      _replayBitmask |= (1 << offset);
    }
  }

  int _guessRoc(int seq) {
    if (_sL < 0x8000) {
      if (seq - _sL > 0x8000) return (_roc == 0) ? 0 : _roc - 1;
      if (_sL - seq > 0x8000) return _roc + 1;
      return _roc;
    } else {
      if (_sL - seq > 0x8000) return _roc + 1;
      if (seq - _sL > 0x8000) return (_roc == 0) ? 0 : _roc - 1;
      return _roc;
    }
  }
}

/// SRTP context for encrypting/decrypting RTP/RTCP (RFC 3711).
final class SrtpContext {
  final SrtpProfile profile;
  final bool isClient;

  // Local (outbound) keys — for encrypting packets we send
  late final Uint8List _encKey;
  late final Uint8List _authKey;
  late final Uint8List _encSalt;  // 14 bytes — KDF output is always 112 bits
  late final Uint8List _rtcpEncKey;
  late final Uint8List _rtcpAuthKey;
  late final Uint8List _rtcpEncSalt;

  // Remote (inbound) keys — for decrypting packets we receive
  late final Uint8List _remoteEncKey;
  late final Uint8List _remoteAuthKey;
  late final Uint8List _remoteEncSalt;
  late final Uint8List _remoteRtcpEncKey;
  late final Uint8List _remoteRtcpAuthKey;
  late final Uint8List _remoteRtcpEncSalt;

  final Map<int, _RocTracker> _rocTrackers = {}; // keyed by SSRC
  int _srtcpSendIndex = 0; // incremented per SRTCP packet sent

  SrtpContext._({required this.profile, required this.isClient});

  /// Master-key length (bytes) for [profile].
  ///
  /// AES-128 profiles (CM-128 and AEAD-AES-128-GCM) use 16-byte keys;
  /// AEAD-AES-256-GCM uses 32-byte keys (RFC 7714 §12.1, §12.3).
  static int _masterKeyLength(SrtpProfile profile) {
    switch (profile) {
      case SrtpProfile.aesCm128HmacSha1_80:
      case SrtpProfile.aesCm128HmacSha1_32:
      case SrtpProfile.aesGcm128:
        return 16;
      case SrtpProfile.aesGcm256:
        return 32;
    }
  }

  /// Master-salt length (bytes) for [profile].
  ///
  /// AES-CM profiles use 14-byte (112-bit) salts (RFC 3711 §8.2);
  /// AEAD-GCM profiles use 12-byte (96-bit) salts (RFC 7714 §12.1, §12.3).
  static int _masterSaltLength(SrtpProfile profile) {
    switch (profile) {
      case SrtpProfile.aesCm128HmacSha1_80:
      case SrtpProfile.aesCm128HmacSha1_32:
        return 14;
      case SrtpProfile.aesGcm128:
      case SrtpProfile.aesGcm256:
        return 12;
    }
  }

  /// Total bytes of TLS-exported keying material this profile consumes:
  /// `2 * (master_key + master_salt)` per RFC 5764 §4.2.
  static int srtpKeyMaterialLength(SrtpProfile profile) =>
      2 * (_masterKeyLength(profile) + _masterSaltLength(profile));

  /// Derive SRTP context from exported DTLS key material.
  ///
  /// [keyMaterial] layout (RFC 5764 §4.2): the per-direction master keys
  /// are concatenated first, followed by the per-direction master salts.
  /// Lengths depend on the profile (RFC 7714 §12 for AEAD-GCM):
  ///
  ///   AES-128-CM-HMAC-SHA1 (60 bytes total):
  ///     client_write_SRTP_master_key   [0..15]
  ///     server_write_SRTP_master_key   [16..31]
  ///     client_write_SRTP_master_salt  [32..45]   (14 bytes)
  ///     server_write_SRTP_master_salt  [46..59]   (14 bytes)
  ///
  ///   AEAD-AES-128-GCM (56 bytes total):
  ///     client_write_SRTP_master_key   [0..15]
  ///     server_write_SRTP_master_key   [16..31]
  ///     client_write_SRTP_master_salt  [32..43]   (12 bytes)
  ///     server_write_SRTP_master_salt  [44..55]   (12 bytes)
  ///
  ///   AEAD-AES-256-GCM (88 bytes total):
  ///     client_write_SRTP_master_key   [0..31]
  ///     server_write_SRTP_master_key   [32..63]
  ///     client_write_SRTP_master_salt  [64..75]   (12 bytes)
  ///     server_write_SRTP_master_salt  [76..87]   (12 bytes)
  factory SrtpContext.fromKeyMaterial({
    required Uint8List keyMaterial,
    required SrtpProfile profile,
    required bool isClient,
  }) {
    final keyLen = _masterKeyLength(profile);
    final saltLen = _masterSaltLength(profile);
    final expected = 2 * (keyLen + saltLen);
    assert(keyMaterial.length >= expected,
        'SRTP key material too short: have ${keyMaterial.length}, '
        'need $expected for $profile');

    final ctx = SrtpContext._(profile: profile, isClient: isClient);

    // Layout: clientKey || serverKey || clientSalt || serverSalt
    final clientKeyOff = 0;
    final serverKeyOff = keyLen;
    final clientSaltOff = 2 * keyLen;
    final serverSaltOff = 2 * keyLen + saltLen;

    // Select keys based on role: local keys for sending, remote keys for receiving
    final Uint8List localMasterKey;
    final Uint8List localMasterSalt;
    final Uint8List remoteMasterKey;
    final Uint8List remoteMasterSalt;
    if (isClient) {
      localMasterKey   = keyMaterial.sublist(clientKeyOff, clientKeyOff + keyLen);
      remoteMasterKey  = keyMaterial.sublist(serverKeyOff, serverKeyOff + keyLen);
      localMasterSalt  = keyMaterial.sublist(clientSaltOff, clientSaltOff + saltLen);
      remoteMasterSalt = keyMaterial.sublist(serverSaltOff, serverSaltOff + saltLen);
    } else {
      localMasterKey   = keyMaterial.sublist(serverKeyOff, serverKeyOff + keyLen);
      remoteMasterKey  = keyMaterial.sublist(clientKeyOff, clientKeyOff + keyLen);
      localMasterSalt  = keyMaterial.sublist(serverSaltOff, serverSaltOff + saltLen);
      remoteMasterSalt = keyMaterial.sublist(clientSaltOff, clientSaltOff + saltLen);
    }

    // Derive local (outbound) session keys using AES-CM KDF (RFC 3711 §4.3.1).
    // The KDF output is always sized to RFC 3711's session-key shapes; for
    // AEAD-GCM only the enc-key (16 or 32 bytes) and enc-salt (12 bytes,
    // truncated below) are actually used at packet time.
    ctx._encKey      = _deriveSessionKey(localMasterKey, localMasterSalt, 0x00, keyLen);
    ctx._authKey     = _deriveSessionKey(localMasterKey, localMasterSalt, 0x01, 20);
    ctx._encSalt     = _deriveSessionKey(localMasterKey, localMasterSalt, 0x02, 14);
    ctx._rtcpEncKey  = _deriveSessionKey(localMasterKey, localMasterSalt, 0x03, keyLen);
    ctx._rtcpAuthKey = _deriveSessionKey(localMasterKey, localMasterSalt, 0x04, 20);
    ctx._rtcpEncSalt = _deriveSessionKey(localMasterKey, localMasterSalt, 0x05, 14);

    // Derive remote (inbound) session keys
    ctx._remoteEncKey      = _deriveSessionKey(remoteMasterKey, remoteMasterSalt, 0x00, keyLen);
    ctx._remoteAuthKey     = _deriveSessionKey(remoteMasterKey, remoteMasterSalt, 0x01, 20);
    ctx._remoteEncSalt     = _deriveSessionKey(remoteMasterKey, remoteMasterSalt, 0x02, 14);
    ctx._remoteRtcpEncKey  = _deriveSessionKey(remoteMasterKey, remoteMasterSalt, 0x03, keyLen);
    ctx._remoteRtcpAuthKey = _deriveSessionKey(remoteMasterKey, remoteMasterSalt, 0x04, 20);
    ctx._remoteRtcpEncSalt = _deriveSessionKey(remoteMasterKey, remoteMasterSalt, 0x05, 14);

    return ctx;
  }

  // ── RTP encryption (RFC 3711 §3.1) ───────────────────────────────────────

  Uint8List encryptRtp(Uint8List rtpPacket) {
    if (rtpPacket.length < 12) return rtpPacket;

    final seq  = _readUint16(rtpPacket, 2);
    final ssrc = _readUint32(rtpPacket, 8);
    final headerLen = _rtpHeaderLength(rtpPacket);
    final payload = rtpPacket.sublist(headerLen);

    final tracker = _rocTrackers.putIfAbsent(ssrc, _RocTracker.new);
    final index = tracker.indexFor(seq);
    tracker.update(seq);

    final Uint8List encPayload;
    if (profile == SrtpProfile.aesGcm128 || profile == SrtpProfile.aesGcm256) {
      // RFC 7714 §8.1: SRTP-GCM IV layout differs from RFC 3711's AES-CM
      // IV — SSRC sits at bytes 2..5, ROC at 6..9, SEQ at 10..11 — and
      // gets XORed with a 12-byte salt.
      final iv = _computeGcmRtpIv(_encSalt, ssrc, index);
      final aad = rtpPacket.sublist(0, headerLen);
      final result = AesGcm.encrypt(_encKey, iv, payload, aad: aad);
      final out = Uint8List(headerLen + result.ciphertext.length + result.tag.length);
      out.setRange(0, headerLen, rtpPacket.sublist(0, headerLen));
      out.setRange(headerLen, headerLen + result.ciphertext.length, result.ciphertext);
      out.setRange(headerLen + result.ciphertext.length, out.length, result.tag);
      return out;
    } else {
      final iv = _computeRtpIv(ssrc, index);
      encPayload = AesCm.encrypt(_encKey, iv, payload);
    }

    // Append authentication tag
    final withoutAuth = Uint8List(headerLen + encPayload.length);
    withoutAuth.setRange(0, headerLen, rtpPacket.sublist(0, headerLen));
    withoutAuth.setRange(headerLen, withoutAuth.length, encPayload);

    final authTagLen = profile == SrtpProfile.aesCm128HmacSha1_80 ? 10 : 4;
    final tag = _computeAuthTag(_authKey, withoutAuth, index, authTagLen);

    final out = Uint8List(withoutAuth.length + authTagLen);
    out.setRange(0, withoutAuth.length, withoutAuth);
    out.setRange(withoutAuth.length, out.length, tag);
    return out;
  }

  Result<Uint8List, CryptoError> decryptRtp(Uint8List srtpPacket) {
    if (srtpPacket.length < 12) {
      return Err(const CryptoError('SRTP: packet too short'));
    }

    final seq  = _readUint16(srtpPacket, 2);
    final ssrc = _readUint32(srtpPacket, 8);
    final headerLen = _rtpHeaderLength(srtpPacket);

    final tracker = _rocTrackers.putIfAbsent(ssrc, _RocTracker.new);
    final index = tracker.indexFor(seq);

    // Replay protection (RFC 3711 §3.3.2)
    if (tracker.isReplay(index)) {
      return Err(const CryptoError('SRTP: replay detected'));
    }

    if (profile == SrtpProfile.aesGcm128 || profile == SrtpProfile.aesGcm256) {
      if (srtpPacket.length < headerLen + 16) {
        return Err(const CryptoError('SRTP: GCM packet too short'));
      }
      // RFC 7714 §8.1: SRTP-GCM IV (see encryptRtp comment).
      final iv = _computeGcmRtpIv(_remoteEncSalt, ssrc, index);
      final aad = srtpPacket.sublist(0, headerLen);
      final ciphertext = srtpPacket.sublist(headerLen, srtpPacket.length - 16);
      final tag = srtpPacket.sublist(srtpPacket.length - 16);
      final plaintext = AesGcm.decrypt(_remoteEncKey, iv, ciphertext, Uint8List.fromList(tag), aad: aad);
      if (plaintext == null) return Err(const CryptoError('SRTP: GCM authentication failed'));
      final out = Uint8List(headerLen + plaintext.length);
      out.setRange(0, headerLen, srtpPacket.sublist(0, headerLen));
      out.setRange(headerLen, out.length, plaintext);
      tracker.update(seq);
      tracker.markReceived(index);
      return Ok(out);
    }

    // AES-CM with HMAC auth
    final authTagLen = profile == SrtpProfile.aesCm128HmacSha1_80 ? 10 : 4;
    if (srtpPacket.length < headerLen + authTagLen) {
      return Err(const CryptoError('SRTP: packet too short for auth tag'));
    }

    final packetBody = srtpPacket.sublist(0, srtpPacket.length - authTagLen);
    final receivedTag = srtpPacket.sublist(srtpPacket.length - authTagLen);
    final expectedTag = _computeAuthTag(_remoteAuthKey, packetBody, index, authTagLen);

    var tagMismatch = 0;
    for (var i = 0; i < authTagLen; i++) {
      tagMismatch |= receivedTag[i] ^ expectedTag[i];
    }
    if (tagMismatch != 0) {
      return Err(const CryptoError('SRTP: authentication failed'));
    }

    final encPayload = packetBody.sublist(headerLen);
    final iv = _computeIv(_remoteEncSalt, ssrc, index);
    final decPayload = AesCm.decrypt(_remoteEncKey, iv, encPayload);

    tracker.update(seq);
    tracker.markReceived(index);

    final out = Uint8List(headerLen + decPayload.length);
    out.setRange(0, headerLen, srtpPacket.sublist(0, headerLen));
    out.setRange(headerLen, out.length, decPayload);
    return Ok(out);
  }

  // ── RTCP encryption (RFC 3711 §3.4) ──────────────────────────────────────

  Uint8List encryptRtcp(Uint8List rtcpPacket) {
    if (rtcpPacket.length < 8) return rtcpPacket;
    // SRTCP index: 32-bit, E bit = 1 (encrypted)
    final srtcpIndex = 1 << 31 | (_srtcpSendIndex++ & 0x7FFFFFFF);
    final ssrc = _readUint32(rtcpPacket, 4);
    final header = rtcpPacket.sublist(0, 8);
    final payload = rtcpPacket.sublist(8);

    final srtcpIndexBytes = Uint8List(4);
    srtcpIndexBytes[0] = (srtcpIndex >> 24) & 0xFF;
    srtcpIndexBytes[1] = (srtcpIndex >> 16) & 0xFF;
    srtcpIndexBytes[2] = (srtcpIndex >>  8) & 0xFF;
    srtcpIndexBytes[3] = srtcpIndex & 0xFF;

    if (profile == SrtpProfile.aesGcm128 || profile == SrtpProfile.aesGcm256) {
      // RFC 7714 §9.1: SRTCP-GCM IV is `0x00 0x00 || SSRC || 0x00 0x00 ||
      // SRTCP_index` XORed with the 12-byte master salt. AAD =
      // RTCP-header || E-bit-tagged-SRTCP-index.
      final iv = _computeGcmRtcpIv(_rtcpEncSalt, ssrc, srtcpIndex & 0x7FFFFFFF);
      final aad = Uint8List(8 + 4);
      aad.setRange(0, 8, header);
      aad.setRange(8, 12, srtcpIndexBytes);
      final result = AesGcm.encrypt(_rtcpEncKey, iv, payload, aad: aad);
      final out = Uint8List(8 + result.ciphertext.length + result.tag.length + 4);
      out.setRange(0, 8, header);
      out.setRange(8, 8 + result.ciphertext.length, result.ciphertext);
      final tagOffset = 8 + result.ciphertext.length;
      out.setRange(tagOffset, tagOffset + result.tag.length, result.tag);
      out.setRange(tagOffset + result.tag.length, out.length, srtcpIndexBytes);
      return out;
    }

    // AES-CM + HMAC-SHA1
    final iv = _computeRtcpIv(ssrc, srtcpIndex & 0x7FFFFFFF);
    final encPayload = AesCm.encrypt(_rtcpEncKey, iv, payload);


    final forAuth = Uint8List(8 + encPayload.length + 4);
    forAuth.setRange(0, 8, header);
    forAuth.setRange(8, 8 + encPayload.length, encPayload);
    forAuth.setRange(8 + encPayload.length, forAuth.length, srtcpIndexBytes);

    final tag = HmacSha1.compute80(_rtcpAuthKey, forAuth);

    final out = Uint8List(forAuth.length + 10);
    out.setRange(0, forAuth.length, forAuth);
    out.setRange(forAuth.length, out.length, tag);
    return out;
  }

  Result<Uint8List, CryptoError> decryptRtcp(Uint8List srtcpPacket) {
    if (profile == SrtpProfile.aesGcm128 || profile == SrtpProfile.aesGcm256) {
      // AES-GCM: [header 8B][ciphertext][GCM tag 16B][srtcpIndex 4B]
      if (srtcpPacket.length < 8 + 16 + 4) {
        return Err(const CryptoError('SRTCP: GCM packet too short'));
      }
      final srtcpIndexOffset = srtcpPacket.length - 4;
      final srtcpIndexWord = _readUint32(srtcpPacket, srtcpIndexOffset);
      final srtcpIndex = srtcpIndexWord & 0x7FFFFFFF;
      final ssrc = _readUint32(srtcpPacket, 4);
      // RFC 7714 §9.1 SRTCP-GCM IV.
      final iv = _computeGcmRtcpIv(_remoteRtcpEncSalt, ssrc, srtcpIndex);
      final header = srtcpPacket.sublist(0, 8);
      final aad = Uint8List(8 + 4);
      aad.setRange(0, 8, header);
      aad.setRange(8, 12, srtcpPacket.sublist(srtcpIndexOffset));
      final ciphertext = srtcpPacket.sublist(8, srtcpIndexOffset - 16);
      final tag = srtcpPacket.sublist(srtcpIndexOffset - 16, srtcpIndexOffset);
      final plaintext = AesGcm.decrypt(_remoteRtcpEncKey, iv, ciphertext, Uint8List.fromList(tag), aad: aad);
      if (plaintext == null) return Err(const CryptoError('SRTCP: GCM authentication failed'));
      final out = Uint8List(8 + plaintext.length);
      out.setRange(0, 8, header);
      out.setRange(8, out.length, plaintext);
      return Ok(out);
    }

    // AES-CM + HMAC-SHA1
    if (srtcpPacket.length < 8 + 4 + 10) {
      return Err(const CryptoError('SRTCP: packet too short'));
    }

    final authTagLen = 10;
    final srtcpIndexOffset = srtcpPacket.length - authTagLen - 4;
    final forAuth = srtcpPacket.sublist(0, srtcpPacket.length - authTagLen);
    final receivedTag = srtcpPacket.sublist(srtcpPacket.length - authTagLen);
    final expectedTag = HmacSha1.compute80(_remoteRtcpAuthKey, forAuth);

    var tagMismatch = 0;
    for (var i = 0; i < authTagLen; i++) {
      tagMismatch |= receivedTag[i] ^ expectedTag[i];
    }
    if (tagMismatch != 0) {
      return Err(const CryptoError('SRTCP: authentication failed'));
    }

    final srtcpIndexWord = _readUint32(srtcpPacket, srtcpIndexOffset);
    final encrypted = (srtcpIndexWord >> 31) != 0;
    final srtcpIndex = srtcpIndexWord & 0x7FFFFFFF;

    final ssrc = _readUint32(srtcpPacket, 4);
    final encPayload = srtcpPacket.sublist(8, srtcpIndexOffset);

    final Uint8List decPayload;
    if (encrypted) {
      final iv = _computeRtcpIv(ssrc, srtcpIndex, remote: true);
      decPayload = AesCm.decrypt(_remoteRtcpEncKey, iv, encPayload);
    } else {
      decPayload = encPayload;
    }

    final out = Uint8List(8 + decPayload.length);
    out.setRange(0, 8, srtcpPacket.sublist(0, 8));
    out.setRange(8, out.length, decPayload);
    return Ok(out);
  }

  // ── Key derivation (RFC 3711 §4.3.1) ─────────────────────────────────────

  /// Derive a session key using AES-128-CM with label.
  ///
  /// k_e = AES-CM(master_key, master_salt XOR (label << 16) || 0x0000)
  static Uint8List _deriveSessionKey(
    Uint8List masterKey,
    Uint8List masterSalt,
    int label,
    int outputLen,
  ) {
    // x = master_salt XOR (label << 16), padded to 14 bytes then extend to 16
    final x = Uint8List(14);
    x.setRange(0, masterSalt.length, masterSalt);
    // XOR label at byte 7 (RFC 3711 §4.3.1: key_id = label || r, aligned right)
    x[7] ^= label & 0xFF;

    // IV = x || 0x0000 (16 bytes total)
    final iv = Uint8List(16);
    iv.setRange(0, 14, x);

    // Generate output bytes by AES-CM counter mode
    final blocks = (outputLen + 15) ~/ 16;
    final out = Uint8List(blocks * 16);
    for (var i = 0; i < blocks; i++) {
      final blockIv = Uint8List.fromList(iv);
      blockIv[15] ^= i; // counter in last byte
      final block = AesCm.encrypt(masterKey, blockIv, Uint8List(16));
      out.setRange(i * 16, (i + 1) * 16, block);
    }
    return out.sublist(0, outputLen);
  }

  // ── IV computation (RFC 3711 §4.1) ───────────────────────────────────────

  /// Compute SRTP IV per RFC 3711 §4.1.1:
  /// IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)
  /// where i * 2^16 = ROC * 2^32 + SEQ * 2^16
  static Uint8List _computeIv(Uint8List salt, int ssrc, int index) {
    final roc = index >> 16;
    final seq = index & 0xFFFF;
    final iv = Uint8List(16);
    iv.setRange(0, 14, salt);
    // SSRC at bytes 4-7 (bits 95-64)
    iv[4] ^= (ssrc >> 24) & 0xFF;
    iv[5] ^= (ssrc >> 16) & 0xFF;
    iv[6] ^= (ssrc >>  8) & 0xFF;
    iv[7] ^= ssrc & 0xFF;
    // ROC at bytes 8-11 (bits 63-32)
    iv[8]  ^= (roc >> 24) & 0xFF;
    iv[9]  ^= (roc >> 16) & 0xFF;
    iv[10] ^= (roc >>  8) & 0xFF;
    iv[11] ^= roc & 0xFF;
    // SEQ at bytes 12-13 (bits 31-16)
    iv[12] ^= (seq >> 8) & 0xFF;
    iv[13] ^= seq & 0xFF;
    return iv;
  }

  Uint8List _computeRtpIv(int ssrc, int index) =>
      _computeIv(_encSalt, ssrc, index);

  Uint8List _computeRtcpIv(int ssrc, int index, {bool remote = false}) {
    final salt = remote ? _remoteRtcpEncSalt : _rtcpEncSalt;
    // IV = k_s XOR (SSRC * 2^64) XOR (SRTCP_index * 2^16)
    // SSRC occupies bytes 4-7 (bits 95-64).
    // SRTCP index (31-bit) shifted left 16 occupies bytes 10-13 (bits 47-16).
    final iv = Uint8List(16);
    iv.setRange(0, 14, salt);
    // SSRC at bytes 4-7
    iv[4] ^= (ssrc >> 24) & 0xFF;
    iv[5] ^= (ssrc >> 16) & 0xFF;
    iv[6] ^= (ssrc >>  8) & 0xFF;
    iv[7] ^= ssrc & 0xFF;
    // SRTCP index << 16: occupies bytes 10-13
    iv[10] ^= (index >> 24) & 0xFF;
    iv[11] ^= (index >> 16) & 0xFF;
    iv[12] ^= (index >>  8) & 0xFF;
    iv[13] ^= index & 0xFF;
    return iv;
  }

  /// Compute the 12-byte SRTP-GCM IV per RFC 7714 §8.1:
  ///
  ///     0  1  2  3  4  5  6  7  8  9 10 11
  ///   +--+--+--+--+--+--+--+--+--+--+--+--+
  ///   |00|00|    SSRC   |     ROC   | SEQ |  XOR salt[0..11]
  ///   +--+--+--+--+--+--+--+--+--+--+--+--+
  ///
  /// [salt] is the session encryption salt (≥ 12 bytes — the KDF returns
  /// 14, of which only the first 12 are XORed in for AEAD-GCM).
  static Uint8List _computeGcmRtpIv(Uint8List salt, int ssrc, int index) {
    final roc = index >> 16;
    final seq = index & 0xFFFF;
    final iv = Uint8List(12);
    for (var i = 0; i < 12; i++) {
      iv[i] = salt[i];
    }
    // SSRC at bytes 2..5
    iv[2] ^= (ssrc >> 24) & 0xFF;
    iv[3] ^= (ssrc >> 16) & 0xFF;
    iv[4] ^= (ssrc >>  8) & 0xFF;
    iv[5] ^=  ssrc        & 0xFF;
    // ROC at bytes 6..9
    iv[6] ^= (roc >> 24) & 0xFF;
    iv[7] ^= (roc >> 16) & 0xFF;
    iv[8] ^= (roc >>  8) & 0xFF;
    iv[9] ^=  roc        & 0xFF;
    // SEQ at bytes 10..11
    iv[10] ^= (seq >> 8) & 0xFF;
    iv[11] ^=  seq       & 0xFF;
    return iv;
  }

  /// Compute the 12-byte SRTCP-GCM IV per RFC 7714 §9.1:
  ///
  ///     0  1  2  3  4  5  6  7  8  9 10 11
  ///   +--+--+--+--+--+--+--+--+--+--+--+--+
  ///   |00|00|    SSRC   |00|00| SRTCP idx |  XOR salt[0..11]
  ///   +--+--+--+--+--+--+--+--+--+--+--+--+
  ///
  /// [index] is the 31-bit SRTCP index (without the E-bit).
  static Uint8List _computeGcmRtcpIv(Uint8List salt, int ssrc, int index) {
    final iv = Uint8List(12);
    for (var i = 0; i < 12; i++) {
      iv[i] = salt[i];
    }
    // SSRC at bytes 2..5
    iv[2] ^= (ssrc >> 24) & 0xFF;
    iv[3] ^= (ssrc >> 16) & 0xFF;
    iv[4] ^= (ssrc >>  8) & 0xFF;
    iv[5] ^=  ssrc        & 0xFF;
    // SRTCP index at bytes 8..11 (with E-bit cleared)
    iv[8]  ^= (index >> 24) & 0xFF;
    iv[9]  ^= (index >> 16) & 0xFF;
    iv[10] ^= (index >>  8) & 0xFF;
    iv[11] ^=  index        & 0xFF;
    return iv;
  }

  static Uint8List _computeAuthTag(Uint8List authKey, Uint8List pkt, int index, int tagLen) {
    final roc = index >> 16;
    final rocBytes = Uint8List(4);
    rocBytes[0] = (roc >> 24) & 0xFF;
    rocBytes[1] = (roc >> 16) & 0xFF;
    rocBytes[2] = (roc >>  8) & 0xFF;
    rocBytes[3] = roc & 0xFF;
    final forAuth = Uint8List(pkt.length + 4);
    forAuth.setRange(0, pkt.length, pkt);
    forAuth.setRange(pkt.length, forAuth.length, rocBytes);
    return HmacSha1.compute(authKey, forAuth).sublist(0, tagLen);
  }

  // ── RTP header parsing ────────────────────────────────────────────────────

  static int _rtpHeaderLength(Uint8List pkt) {
    var len = 12;
    // CSRC count
    len += (pkt[0] & 0x0F) * 4;
    // Extension header
    if ((pkt[0] & 0x10) != 0 && pkt.length >= len + 4) {
      final extLen = _readUint16(pkt, len + 2);
      len += 4 + extLen * 4;
    }
    return len;
  }

  static int _readUint16(Uint8List d, int o) => (d[o] << 8) | d[o + 1];

  static int _readUint32(Uint8List d, int o) =>
      ((d[o] << 24) | (d[o+1] << 16) | (d[o+2] << 8) | d[o+3]) >>> 0;
}
