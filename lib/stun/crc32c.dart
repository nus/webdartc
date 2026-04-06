import 'dart:typed_data';

/// CRC-32 (ITU V.42 / ISO 3309) — used by STUN FINGERPRINT (RFC 5389 §15.5).
///
/// Pure Dart table-driven implementation using the standard CRC-32 polynomial.
/// Note: Despite the file name, STUN uses standard CRC-32, not CRC-32c.
abstract final class Crc32c {
  Crc32c._();

  static final List<int> _table = _buildTable();

  static List<int> _buildTable() {
    const poly = 0xEDB88320; // Standard CRC-32 reflected polynomial
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

  /// Compute CRC-32 of [data].
  static int compute(Uint8List data) {
    var crc = 0xFFFFFFFF;
    for (final byte in data) {
      crc = _table[(crc ^ byte) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF;
  }
}
