import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:webdartc/crypto/hkdf.dart';
import 'package:webdartc/crypto/sha256.dart';
import 'package:webdartc/dtls/v13/srtp_export.dart';

void main() {
  Uint8List bytes(List<int> v) => Uint8List.fromList(v);
  String hexOf(Uint8List b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  group('DtlsV13SrtpExport.export', () {
    final exporterMasterSecret = bytes(
      List<int>.generate(32, (i) => 0xA0 ^ i),
    );

    test('default length is 60 bytes (SRTP_AES_CM_128_HMAC_SHA1_80)', () {
      final out = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
      );
      expect(out.length, equals(60));
    });

    test('output is deterministic', () {
      final a = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
      );
      final b = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
      );
      expect(a, equals(b));
    });

    test('different exporter secrets yield different outputs', () {
      final ems2 = Uint8List.fromList(exporterMasterSecret)..[0] ^= 0x01;
      final a = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
      );
      final b = DtlsV13SrtpExport.export(exporterMasterSecret: ems2);
      expect(a, isNot(equals(b)));
    });

    test('different labels yield different outputs', () {
      final a = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
        label: 'EXTRACTOR-dtls_srtp',
      );
      final b = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
        label: 'OTHER-LABEL',
      );
      expect(a, isNot(equals(b)));
    });

    test('different contexts yield different outputs', () {
      final a = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
        context: Uint8List(0),
      );
      final b = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
        context: bytes([0x01]),
      );
      expect(a, isNot(equals(b)));
    });

    test('matches hand-computed two-step HKDF (RFC 8446 §7.5)', () {
      // Reproduce the exporter spec by hand using the lower-level Hkdf
      // primitives — this guards against accidental drift in
      // DtlsV13SrtpExport.export.
      const label = 'EXTRACTOR-dtls_srtp';
      const length = 60;
      final emptyHash = Sha256.hash(Uint8List(0));
      final perLabel = Hkdf.expandLabel(
        secret: exporterMasterSecret,
        label: label,
        context: emptyHash,
        length: 32,
      );
      final expected = Hkdf.expandLabel(
        secret: perLabel,
        label: 'exporter',
        context: emptyHash, // empty context_value
        length: length,
      );
      final actual = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
      );
      expect(hexOf(actual), equals(hexOf(expected)));
    });

    test('honours non-default length and context', () {
      final out = DtlsV13SrtpExport.export(
        exporterMasterSecret: exporterMasterSecret,
        length: 32,
        context: bytes([1, 2, 3, 4]),
      );
      expect(out.length, equals(32));

      final emptyHash = Sha256.hash(Uint8List(0));
      final perLabel = Hkdf.expandLabel(
        secret: exporterMasterSecret,
        label: DtlsV13SrtpExport.dtlsSrtpLabel,
        context: emptyHash,
        length: 32,
      );
      final expected = Hkdf.expandLabel(
        secret: perLabel,
        label: 'exporter',
        context: Sha256.hash(bytes([1, 2, 3, 4])),
        length: 32,
      );
      expect(out, equals(expected));
    });
  });
}
