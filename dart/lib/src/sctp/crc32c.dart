import 'dart:typed_data';

/// CRC-32c (Castagnoli) for SCTP checksums (RFC 4960 Appendix B).
///
/// Uses reflected Castagnoli polynomial 0x82F63B78.
abstract final class SctpCrc32c {
  SctpCrc32c._();

  static final List<int> _table = _buildTable();

  static List<int> _buildTable() {
    const poly = 0x82F63B78;
    final table = List<int>.filled(256, 0);
    for (var i = 0; i < 256; i++) {
      var crc = i;
      for (var j = 0; j < 8; j++) {
        crc = (crc & 1) != 0 ? (crc >>> 1) ^ poly : crc >>> 1;
      }
      table[i] = crc;
    }
    return table;
  }

  /// Compute CRC-32c of [data].
  static int compute(Uint8List data) {
    var crc = 0xFFFFFFFF;
    for (final byte in data) {
      crc = _table[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
  }
}
