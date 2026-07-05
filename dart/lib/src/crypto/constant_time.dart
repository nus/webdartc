/// Constant-time byte comparison shared by every MAC/tag verification
/// (SRTP auth tags, DTLS Finished verify_data, HMAC cookies, AEAD tags).
library;

import 'dart:typed_data';

/// Whether [a] and [b] are equal, in time independent of *where* they
/// differ. Runtime depends only on the lengths (a length mismatch returns
/// false immediately — lengths are public). The XOR-accumulate loop is the
/// timing-attack contract: never rewrite it with an early return.
bool constantTimeEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
