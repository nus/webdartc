/// Hex encoding of byte sequences, two digits per byte.
///
/// Consolidates the `toRadixString(16).padLeft(2, '0')` join that protocol
/// modules re-implemented for transaction-id keys, digest strings, debug
/// dumps ([separator] `' '`), and certificate fingerprints ([separator]
/// `':'` + [upperCase], RFC 8122 `a=fingerprint` format).
library;

/// Lowercase hex string of [bytes]; [separator] between bytes, [upperCase]
/// switches to uppercase digits.
String hex(
  Iterable<int> bytes, {
  String separator = '',
  bool upperCase = false,
}) {
  final joined = bytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join(separator);
  return upperCase ? joined.toUpperCase() : joined;
}
