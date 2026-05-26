/// Fuzz tests for all binary parsers.
///
/// Verifies that parsers never throw unhandled exceptions on arbitrary input.
/// Uses random byte sequences, mutation of valid packets, and edge-case sizes.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/webdartc.dart';

// Not exported via webdartc.dart — import directly.
import 'package:webdartc/dtls/record.dart';
import 'package:webdartc/sctp/chunk.dart';
import 'package:webdartc/turn/channel_data.dart';

/// Number of random iterations per test.
const int _iterations = 10000;

/// Max random packet size.
const int _maxSize = 1024;

final _rng = Random(42); // fixed seed for reproducibility

Uint8List _randomBytes(int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = _rng.nextInt(256);
  }
  return bytes;
}

/// Generate a random-length random packet (0..[maxSize]).
Uint8List _randomPacket([int maxSize = _maxSize]) =>
    _randomBytes(_rng.nextInt(maxSize + 1));

/// Mutate a valid packet by flipping random bits.
Uint8List _mutate(Uint8List valid, {int mutations = 5}) {
  final copy = Uint8List.fromList(valid);
  for (var i = 0; i < mutations; i++) {
    if (copy.isEmpty) break;
    final pos = _rng.nextInt(copy.length);
    copy[pos] ^= (1 << _rng.nextInt(8));
  }
  return copy;
}

/// Truncate a valid packet at a random position.
Uint8List _truncate(Uint8List valid) {
  if (valid.isEmpty) return valid;
  final len = _rng.nextInt(valid.length);
  return valid.sublist(0, len);
}

void main() {
  // ── STUN ──────────────────────────────────────────────────────────────────

  group('Fuzz: STUN', () {
    test('StunParser.isStun never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        StunParser.isStun(_randomPacket());
      }
    });

    test('StunParser.parse never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        StunParser.parse(_randomPacket());
      }
    });

    test('StunParser.parse never throws on mutated valid STUN', () {
      final txId = _randomBytes(12);
      final valid = StunMessageBuilder.build(StunMessage(
        type: 0x0001,
        transactionId: txId,
        attributes: const [],
      ));

      for (var i = 0; i < _iterations; i++) {
        StunParser.parse(_mutate(valid));
      }
    });

    test('StunParser.parse never throws on truncated valid STUN', () {
      final txId = _randomBytes(12);
      final valid = StunMessageBuilder.build(StunMessage(
        type: 0x0001,
        transactionId: txId,
        attributes: [
          const UsernameAttr('user:peer'),
          PriorityAttr(0x6e0001ff),
          const UseCandidateAttr(),
        ],
      ));

      for (var i = 0; i < _iterations; i++) {
        StunParser.parse(_truncate(valid));
      }
    });

    test('StunParser.parse handles empty input', () {
      StunParser.parse(Uint8List(0));
    });

    test('StunParser.parse handles single byte', () {
      for (var b = 0; b < 256; b++) {
        StunParser.parse(Uint8List.fromList([b]));
      }
    });
  });

  // ── RTP ───────────────────────────────────────────────────────────────────

  group('Fuzz: RTP', () {
    test('RtpParser.parseRtp never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        RtpParser.parseRtp(_randomPacket());
      }
    });

    test('RtpParser.isRtcp never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        RtpParser.isRtcp(_randomPacket());
      }
    });

    test('RtpParser.isDtls never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        RtpParser.isDtls(_randomPacket());
      }
    });

    test('RtpParser.parseRtp never throws on mutated valid RTP', () {
      final valid = RtpPacket(
        version: 2,
        padding: false,
        extension: false,
        csrcs: const [],
        marker: false,
        payloadType: 111,
        sequenceNumber: 1000,
        timestamp: 160000,
        ssrc: 0x12345678,
        payload: _randomBytes(160),
      ).build();

      for (var i = 0; i < _iterations; i++) {
        RtpParser.parseRtp(_mutate(valid));
      }
    });

    test('RtpParser.parseRtp handles RTP with extensions (mutated)', () {
      final valid = RtpPacket(
        version: 2,
        padding: false,
        extension: true,
        csrcs: const [0xAABBCCDD],
        marker: true,
        payloadType: 96,
        sequenceNumber: 65535,
        timestamp: 0xFFFFFFFF,
        ssrc: 0xDEADBEEF,
        headerExtension: RtpExtension(
          profile: 0xBEDE,
          data: _randomBytes(8),
        ),
        payload: _randomBytes(100),
      ).build();

      for (var i = 0; i < _iterations; i++) {
        RtpParser.parseRtp(_mutate(valid));
      }
    });

    test('RtpParser.parseRtp handles truncated input', () {
      final valid = RtpPacket(
        version: 2,
        padding: true,
        extension: true,
        csrcs: const [1, 2, 3],
        marker: false,
        payloadType: 96,
        sequenceNumber: 100,
        timestamp: 48000,
        ssrc: 1,
        headerExtension: RtpExtension(profile: 0xBEDE, data: _randomBytes(16)),
        payload: _randomBytes(200),
      ).build();

      for (var i = 0; i < _iterations; i++) {
        RtpParser.parseRtp(_truncate(valid));
      }
    });
  });

  // ── RTCP ──────────────────────────────────────────────────────────────────

  group('Fuzz: RTCP', () {
    test('RtpParser.parseRtcp never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        RtpParser.parseRtcp(_randomPacket());
      }
    });

    test('RtpParser.parseRtcp never throws on mutated valid compound RTCP', () {
      final rr = RtcpReceiverReport(ssrc: 0x12345678).build();
      final sdes = RtcpSdes(chunks: [
        RtcpSdesChunk(ssrc: 0x12345678, items: {1: 'test'}),
      ]).build();
      final compound = Uint8List(rr.length + sdes.length);
      compound.setRange(0, rr.length, rr);
      compound.setRange(rr.length, compound.length, sdes);

      for (var i = 0; i < _iterations; i++) {
        RtpParser.parseRtcp(_mutate(compound));
      }
    });

    test('RtpParser.parseRtcp never throws on truncated compound RTCP', () {
      final rr = RtcpReceiverReport(ssrc: 1).build();
      final sdes = RtcpSdes(chunks: [
        RtcpSdesChunk(ssrc: 1, items: {1: 'x'}),
      ]).build();
      final compound = Uint8List(rr.length + sdes.length);
      compound.setRange(0, rr.length, rr);
      compound.setRange(rr.length, compound.length, sdes);

      for (var i = 0; i < _iterations; i++) {
        RtpParser.parseRtcp(_truncate(compound));
      }
    });
  });

  // ── DTLS ──────────────────────────────────────────────────────────────────

  group('Fuzz: DTLS', () {
    test('DtlsRecord.parse never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        DtlsRecord.parse(_randomPacket(), 0);
      }
    });

    test('DtlsHandshakeHeader.parse never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        DtlsHandshakeHeader.parse(_randomPacket());
      }
    });

    test('DtlsRecord.parse never throws on mutated valid record', () {
      final valid = DtlsRecord(
        contentType: DtlsContentType.handshake,
        version: 0xFEFD,
        epoch: 0,
        sequenceNumber: 1,
        fragment: _randomBytes(50),
      ).encode();

      for (var i = 0; i < _iterations; i++) {
        DtlsRecord.parse(_mutate(valid), 0);
      }
    });

    test('DtlsHandshakeHeader.parse never throws on mutated valid header', () {
      final valid = DtlsHandshakeHeader(
        msgType: DtlsHandshakeType.clientHello,
        length: 100,
        messageSeq: 0,
        fragmentOffset: 0,
        fragmentLength: 100,
        body: _randomBytes(100),
      ).encode();

      for (var i = 0; i < _iterations; i++) {
        DtlsHandshakeHeader.parse(_mutate(valid));
      }
    });

    test('DtlsRecord.parse with random offset', () {
      for (var i = 0; i < _iterations; i++) {
        final data = _randomPacket(256);
        final offset = data.isEmpty ? 0 : _rng.nextInt(data.length);
        DtlsRecord.parse(data, offset);
      }
    });
  });

  // ── SCTP ──────────────────────────────────────────────────────────────────

  group('Fuzz: SCTP', () {
    test('SctpCommonHeader.parse never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        SctpCommonHeader.parse(_randomPacket());
      }
    });

    test('parseChunks never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        parseChunks(_randomPacket(), 0);
      }
    });

    test('parseChunks never throws with random offset', () {
      for (var i = 0; i < _iterations; i++) {
        final data = _randomPacket(512);
        final offset = data.isEmpty ? 0 : _rng.nextInt(data.length);
        parseChunks(data, offset);
      }
    });

    test('parseChunks never throws on mutated valid INIT chunk', () {
      final initChunk = SctpInitChunk(
        initiateTag: 0xABCD1234,
        advertisedRecvWindowCredit: 65535,
        numOutboundStreams: 1,
        numInboundStreams: 1,
        initialTsn: 1,
      ).encode();

      for (var i = 0; i < _iterations; i++) {
        parseChunks(_mutate(initChunk), 0);
      }
    });

    test('parseChunks never throws on mutated valid DATA chunk', () {
      final dataChunk = SctpDataChunk(
        flags: SctpDataChunk.flagBegin | SctpDataChunk.flagEnd,
        tsn: 100,
        streamId: 0,
        streamSeqNum: 0,
        ppid: 51,
        userData: _randomBytes(64),
      ).encode();

      for (var i = 0; i < _iterations; i++) {
        parseChunks(_mutate(dataChunk), 0);
      }
    });

    test('parseChunks never throws on mutated valid SACK chunk', () {
      final sack = SctpSackChunk(
        cumulativeTsnAck: 50,
        advertisedRecvWindowCredit: 65535,
        gapAckBlocks: const [(2, 3), (5, 7)],
        duplicateTsns: const [10, 20],
      ).encode();

      for (var i = 0; i < _iterations; i++) {
        parseChunks(_mutate(sack), 0);
      }
    });

    test('parseChunks never throws on concatenated random chunks', () {
      for (var i = 0; i < _iterations; i++) {
        final numChunks = _rng.nextInt(5) + 1;
        final parts = <int>[];
        for (var j = 0; j < numChunks; j++) {
          parts.addAll(_randomBytes(_rng.nextInt(64) + 4));
        }
        parseChunks(Uint8List.fromList(parts), 0);
      }
    });
  });

  // ── DCEP ──────────────────────────────────────────────────────────────────

  group('Fuzz: DCEP', () {
    test('DcepOpenMessage.parse never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        DcepOpenMessage.parse(_randomPacket());
      }
    });

    test('DcepAckMessage.isDcepAck never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        DcepAckMessage.isDcepAck(_randomPacket());
      }
    });

    test('DcepOpenMessage.parse never throws on mutated valid message', () {
      final valid = const DcepOpenMessage(
        channelType: DcepChannelType.reliable,
        priority: 256,
        label: 'test-channel',
        protocol: '',
      ).encode();

      for (var i = 0; i < _iterations; i++) {
        DcepOpenMessage.parse(_mutate(valid));
      }
    });

    test('DcepOpenMessage.parse handles empty input', () {
      DcepOpenMessage.parse(Uint8List(0));
    });
  });

  // ── SDP (text-based) ─────────────────────────────────────────────────────

  group('Fuzz: SDP', () {
    test('SdpParser.parse never throws on random strings', () {
      for (var i = 0; i < _iterations; i++) {
        final bytes = _randomBytes(_rng.nextInt(512));
        // Filter to printable ASCII + newlines to form plausible SDP
        final text = String.fromCharCodes(
          bytes.map((b) => b < 0x20 ? (b % 2 == 0 ? 0x0A : 0x3D) : b),
        );
        SdpParser.parse(text);
      }
    });

    test('SdpParser.parse never throws on mutated valid SDP', () {
      const validSdp = 'v=0\r\n'
          'o=- 123456 2 IN IP4 127.0.0.1\r\n'
          's=-\r\n'
          't=0 0\r\n'
          'a=group:BUNDLE 0\r\n'
          'm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n'
          'c=IN IP4 0.0.0.0\r\n'
          'a=mid:0\r\n'
          'a=sendrecv\r\n'
          'a=rtpmap:111 opus/48000/2\r\n'
          'a=ice-ufrag:abcd\r\n'
          'a=ice-pwd:efghijklmnopqrstuvwx\r\n'
          'a=fingerprint:sha-256 AA:BB:CC:DD\r\n'
          'a=setup:actpass\r\n'
          'a=rtcp-mux\r\n';

      final validBytes = Uint8List.fromList(validSdp.codeUnits);
      for (var i = 0; i < _iterations; i++) {
        final mutated = _mutate(validBytes, mutations: 3);
        SdpParser.parse(String.fromCharCodes(mutated));
      }
    });

    test('SdpParser.parseCandidate never throws on random strings', () {
      for (var i = 0; i < _iterations; i++) {
        final bytes = _randomBytes(_rng.nextInt(256));
        final text = String.fromCharCodes(
          bytes.map((b) => b < 0x20 ? 0x20 : b),
        );
        SdpParser.parseCandidate(text);
      }
    });

    test('SdpParser.parse handles empty string', () {
      SdpParser.parse('');
    });

    test('SdpParser.parse handles very long lines', () {
      final longLine = 'a=${'x' * 10000}\r\n';
      SdpParser.parse('v=0\r\n$longLine');
    });
  });

  // ── TURN ──────────────────────────────────────────────────────────────────

  group('Fuzz: TURN ChannelData', () {
    test('isChannelData never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        isChannelData(_randomPacket());
      }
    });

    test('parseChannelData never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        parseChannelData(_randomPacket());
      }
    });

    test('parseChannelData never throws on mutated valid frame', () {
      final valid = buildChannelData(0x4001, _randomBytes(200));
      for (var i = 0; i < _iterations; i++) {
        parseChannelData(_mutate(valid));
      }
    });

    test('parseChannelData never throws on truncated valid frame', () {
      final valid = buildChannelData(0x4001, _randomBytes(200));
      for (var i = 0; i < _iterations; i++) {
        parseChannelData(_truncate(valid));
      }
    });

    test('all-zeros and all-0xFF buffers (0-32 bytes)', () {
      for (var size = 0; size <= 32; size++) {
        parseChannelData(Uint8List(size));
        isChannelData(Uint8List(size));
        final ff = Uint8List(size)..fillRange(0, size, 0xFF);
        parseChannelData(ff);
        isChannelData(ff);
      }
    });

    test('encode→parse round-trip', () {
      for (var i = 0; i < _iterations; i++) {
        final channel =
            channelNumberMin + _rng.nextInt(channelNumberMax - channelNumberMin + 1);
        final payload = _randomBytes(_rng.nextInt(500));
        final frame = buildChannelData(channel, payload, pad: _rng.nextBool());
        final parsed = parseChannelData(frame);
        expect(parsed, isNotNull, reason: 'round-trip failed at iteration $i');
        expect(parsed!.channel, equals(channel));
        expect(parsed.payload, equals(payload));
      }
    });
  });

  // ── TURN-TCP framing (RFC 5766 §11.5) ────────────────────────────────────
  //
  // `turnTcpFrameLength` runs on every chunk of bytes a TURN-TCP server
  // emits, so it has to stay total: no exceptions, no negatives, no
  // overflows, no infinite loops in the surrounding demux. A malicious
  // server should never crash the client by sending garbage.

  group('Fuzz: TURN-TCP framing', () {
    test('turnTcpFrameLength never throws on random input', () {
      for (var i = 0; i < _iterations; i++) {
        turnTcpFrameLength(_randomPacket());
      }
    });

    test('turnTcpFrameLength always returns non-negative totals', () {
      for (var i = 0; i < _iterations; i++) {
        final r = turnTcpFrameLength(_randomPacket());
        if (r is TurnTcpFrameLengthKnown) {
          // 4 = ChannelData with empty payload (zero pad). Otherwise
          // STUN-header (20) + body-len, or ChannelData header + body
          // padded — all by construction ≥ 4.
          expect(r.totalBytes, greaterThanOrEqualTo(4));
          // 65535 is the largest body length the 16-bit field can
          // describe; STUN tops out at 20 + 65535 = 65555 and
          // ChannelData at (4 + 65535 + 3) & ~3 = 65540.
          expect(r.totalBytes, lessThanOrEqualTo(65555));
        }
      }
    });

    test('turnTcpFrameLength handles empty + sub-header buffers', () {
      for (var len = 0; len < 4; len++) {
        expect(turnTcpFrameLength(_randomBytes(len)),
            isA<TurnTcpFrameLengthNeedMore>());
      }
    });

    test('demux loop never infinite-loops or unbounded-grows on garbage', () {
      // Simulate the `_TurnTcpConnection._drain` loop against a random
      // stream split into random chunks. The drain must either consume
      // bytes, ask for more, or terminate via the malformed branch —
      // never neither.
      const int maxStreamBytes = 4096;
      const int maxIterationsPerStream = 200;
      for (var stream = 0; stream < 200; stream++) {
        var buffer = Uint8List(0);
        final chunks = <Uint8List>[];
        var streamLen = 0;
        while (streamLen < maxStreamBytes) {
          final chunkLen = 1 + _rng.nextInt(64);
          final chunk = _randomBytes(chunkLen);
          chunks.add(chunk);
          streamLen += chunkLen;
        }
        for (final chunk in chunks) {
          final next = Uint8List(buffer.length + chunk.length)
            ..setRange(0, buffer.length, buffer)
            ..setRange(buffer.length, buffer.length + chunk.length, chunk);
          buffer = next;
          var drained = 0;
          var malformed = false;
          while (drained < maxIterationsPerStream) {
            final r = turnTcpFrameLength(buffer);
            if (r is TurnTcpFrameLengthNeedMore) break;
            if (r is TurnTcpFrameLengthMalformed) {
              malformed = true;
              break;
            }
            final known = r as TurnTcpFrameLengthKnown;
            if (buffer.length < known.totalBytes) break;
            buffer = buffer.length == known.totalBytes
                ? Uint8List(0)
                : Uint8List.fromList(
                    Uint8List.sublistView(buffer, known.totalBytes));
            drained++;
          }
          expect(drained, lessThan(maxIterationsPerStream),
              reason: 'demux entered a hot loop on stream $stream');
          if (malformed) break;
        }
      }
    });
  });

  group('Fuzz: TURN STUN messages', () {
    // Allocate request shape that exercises every new TURN attribute on
    // the parse path. Mutating it covers the new switch arms in the
    // parser against arbitrary bit flips in attribute lengths / types /
    // values.
    final txId = _randomBytes(12);
    final allocateRequest = StunMessageBuilder.build(StunMessage(
      type: StunMessageType.allocateRequest,
      transactionId: txId,
      attributes: [
        const RequestedTransportAttr(17),
        const LifetimeAttr(600),
        const DontFragmentAttr(),
        const UsernameAttr('alice'),
        const RealmAttr('example.org'),
        NonceAttr(Uint8List.fromList('deadbeef'.codeUnits)),
        XorPeerAddress(
          address: IpAddress.parse('192.0.2.1'),
          port: 12345,
        ),
        DataAttr(_randomBytes(64)),
      ],
    ));

    test('StunParser.parse never throws on mutated TURN Allocate', () {
      for (var i = 0; i < _iterations; i++) {
        StunParser.parse(_mutate(allocateRequest));
      }
    });

    test('StunParser.parse never throws on truncated TURN Allocate', () {
      for (var i = 0; i < _iterations; i++) {
        StunParser.parse(_truncate(allocateRequest));
      }
    });

    // Data indication is the TURN receive-path message — relayed peer
    // bytes arrive wrapped in XOR-PEER-ADDRESS + DATA attributes.
    test('StunParser.parse never throws on mutated TURN DataIndication',
        () {
      final dataInd = StunMessageBuilder.build(StunMessage(
        type: StunMessageType.dataIndication,
        transactionId: _randomBytes(12),
        attributes: [
          XorPeerAddress(
            address: IpAddress.parse('203.0.113.7'),
            port: 49152,
          ),
          DataAttr(_randomBytes(800)),
        ],
      ));
      for (var i = 0; i < _iterations; i++) {
        StunParser.parse(_mutate(dataInd));
      }
    });
  });

  // ── Demux classification ──────────────────────────────────────────────────

  group('Fuzz: Demux classification', () {
    test('isStun/isRtcp/isDtls never throw and are consistent', () {
      for (var i = 0; i < _iterations; i++) {
        final pkt = _randomPacket();
        StunParser.isStun(pkt);
        RtpParser.isRtcp(pkt);
        RtpParser.isDtls(pkt);
      }
    });

    test('empty packet classification', () {
      final empty = Uint8List(0);
      expect(StunParser.isStun(empty), isFalse);
      expect(RtpParser.isRtcp(empty), isFalse);
      expect(RtpParser.isDtls(empty), isFalse);
    });

    test('single byte classification', () {
      for (var b = 0; b < 256; b++) {
        final pkt = Uint8List.fromList([b]);
        StunParser.isStun(pkt);
        RtpParser.isRtcp(pkt);
        RtpParser.isDtls(pkt);
      }
    });
  });

  // ── Encode→Parse round-trip fuzz ─────────────────────────────────────────

  group('Fuzz: Round-trip encode→parse', () {
    test('RTP encode→parse round-trip with random payloads', () {
      for (var i = 0; i < _iterations; i++) {
        final packet = RtpPacket(
          version: 2,
          padding: false,
          extension: false,
          csrcs: const [],
          marker: _rng.nextBool(),
          payloadType: _rng.nextInt(128),
          sequenceNumber: _rng.nextInt(65536),
          timestamp: _rng.nextInt(0x100000000),
          ssrc: _rng.nextInt(0x100000000),
          payload: _randomBytes(_rng.nextInt(200)),
        );
        final raw = packet.build();
        final result = RtpParser.parseRtp(raw);
        expect(result.isOk, isTrue, reason: 'round-trip failed at iteration $i');
        final parsed = result.value;
        expect(parsed.payloadType, equals(packet.payloadType));
        expect(parsed.sequenceNumber, equals(packet.sequenceNumber));
        expect(parsed.ssrc, equals(packet.ssrc));
      }
    });

    test('STUN encode→parse round-trip with random attributes', () {
      for (var i = 0; i < 1000; i++) {
        final txId = _randomBytes(12);
        final attrs = <StunAttribute>[];
        if (_rng.nextBool()) attrs.add(UsernameAttr('user${_rng.nextInt(9999)}'));
        if (_rng.nextBool()) attrs.add(PriorityAttr(_rng.nextInt(0x100000000)));
        if (_rng.nextBool()) attrs.add(const UseCandidateAttr());

        final msg = StunMessage(
          type: 0x0001,
          transactionId: txId,
          attributes: attrs,
        );
        final raw = StunMessageBuilder.build(msg);
        final result = StunParser.parse(raw);
        expect(result.isOk, isTrue, reason: 'round-trip failed at iteration $i');
        expect(result.value.type, equals(0x0001));
      }
    });

    test('DTLS record encode→parse round-trip with random fragments', () {
      for (var i = 0; i < _iterations; i++) {
        final record = DtlsRecord(
          contentType: [20, 21, 22, 23][_rng.nextInt(4)],
          version: 0xFEFD,
          epoch: _rng.nextInt(4),
          sequenceNumber: _rng.nextInt(0x1000000),
          fragment: _randomBytes(_rng.nextInt(100)),
        );
        final raw = record.encode();
        final parsed = DtlsRecord.parse(raw, 0);
        expect(parsed, isNotNull, reason: 'round-trip failed at iteration $i');
        expect(parsed!.contentType, equals(record.contentType));
        expect(parsed.epoch, equals(record.epoch));
      }
    });

    test('SCTP DATA chunk encode→parseChunks round-trip', () {
      for (var i = 0; i < _iterations; i++) {
        final chunk = SctpDataChunk(
          flags: _rng.nextInt(8),
          tsn: _rng.nextInt(0x100000000),
          streamId: _rng.nextInt(65536),
          streamSeqNum: _rng.nextInt(65536),
          ppid: _rng.nextInt(0x100000000),
          userData: _randomBytes(_rng.nextInt(100)),
        );
        final raw = chunk.encode();
        final chunks = parseChunks(raw, 0);
        expect(chunks, isNotEmpty, reason: 'round-trip failed at iteration $i');
        expect(chunks.first, isA<SctpDataChunk>());
        final parsed = chunks.first as SctpDataChunk;
        expect(parsed.tsn, equals(chunk.tsn));
        expect(parsed.streamId, equals(chunk.streamId));
      }
    });

    test('DCEP encode→parse round-trip with random labels', () {
      for (var i = 0; i < 1000; i++) {
        final labelLen = _rng.nextInt(50);
        final label = String.fromCharCodes(
          List.generate(labelLen, (_) => 0x41 + _rng.nextInt(26)),
        );
        final msg = DcepOpenMessage(
          channelType: DcepChannelType.values[_rng.nextInt(DcepChannelType.values.length)],
          priority: _rng.nextInt(65536),
          label: label,
          protocol: _rng.nextBool() ? 'binary' : '',
        );
        final raw = msg.encode();
        final parsed = DcepOpenMessage.parse(raw);
        expect(parsed, isNotNull, reason: 'round-trip failed at iteration $i');
        expect(parsed!.label, equals(label));
      }
    });
  });

  // ── Boundary values ───────────────────────────────────────────────────────

  group('Fuzz: Boundary values', () {
    test('RTP with varying CSRC count (0-15)', () {
      for (var cc = 0; cc <= 15; cc++) {
        final pkt = Uint8List(12 + cc * 4 + 10);
        pkt[0] = 0x80 | cc; // version=2, cc
        pkt[1] = 96;
        for (var j = 0; j < cc; j++) {
          final o = 12 + j * 4;
          pkt[o] = _rng.nextInt(256);
          pkt[o + 1] = _rng.nextInt(256);
          pkt[o + 2] = _rng.nextInt(256);
          pkt[o + 3] = _rng.nextInt(256);
        }
        RtpParser.parseRtp(pkt);
      }
    });

    test('RTCP with varying report count (0-31)', () {
      for (var rc = 0; rc <= 31; rc++) {
        final minLen = 8 + rc * 24;
        final pkt = Uint8List(minLen);
        pkt[0] = 0x80 | rc;
        pkt[1] = 201; // RR
        final wordLen = (minLen ~/ 4) - 1;
        pkt[2] = (wordLen >> 8) & 0xFF;
        pkt[3] = wordLen & 0xFF;
        RtpParser.parseRtcp(pkt);
      }
    });

    test('SCTP chunk length claims larger than data', () {
      final data = Uint8List(8);
      data[0] = 0x00; // DATA
      data[1] = 0x03; // flags
      data[2] = 0x03; // length=1000 >> 8
      data[3] = 0xE8; // length=1000 & 0xFF
      parseChunks(data, 0);
    });

    test('DTLS record with length 0', () {
      final pkt = Uint8List(13);
      pkt[0] = DtlsContentType.handshake;
      pkt[1] = 0xFE;
      pkt[2] = 0xFD;
      final record = DtlsRecord.parse(pkt, 0);
      expect(record, isNotNull);
      expect(record!.fragment.length, equals(0));
    });

    test('all-zeros packets (0-64 bytes)', () {
      for (var size = 0; size <= 64; size++) {
        final pkt = Uint8List(size);
        StunParser.isStun(pkt);
        StunParser.parse(pkt);
        RtpParser.parseRtp(pkt);
        RtpParser.parseRtcp(pkt);
        RtpParser.isRtcp(pkt);
        RtpParser.isDtls(pkt);
        DtlsRecord.parse(pkt, 0);
        DtlsHandshakeHeader.parse(pkt);
        SctpCommonHeader.parse(pkt);
        parseChunks(pkt, 0);
        DcepOpenMessage.parse(pkt);
        DcepAckMessage.isDcepAck(pkt);
      }
    });

    test('all-0xFF packets (0-64 bytes)', () {
      for (var size = 0; size <= 64; size++) {
        final pkt = Uint8List(size)..fillRange(0, size, 0xFF);
        StunParser.isStun(pkt);
        StunParser.parse(pkt);
        RtpParser.parseRtp(pkt);
        RtpParser.parseRtcp(pkt);
        DtlsRecord.parse(pkt, 0);
        DtlsHandshakeHeader.parse(pkt);
        SctpCommonHeader.parse(pkt);
        parseChunks(pkt, 0);
        DcepOpenMessage.parse(pkt);
      }
    });
  });
}
