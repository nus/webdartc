/// Pending STUN transaction bookkeeping shared by ICE and TURN.
///
/// Both state machines key outstanding requests by the 12-byte STUN
/// transaction id (RFC 5389 §6) and keep a "sent at + prune stale" table;
/// this consolidates the id normalization and the table so the two sides
/// can't drift (ICE used hex keys, TURN used `String.fromCharCodes`).
library;

import 'dart:typed_data';

import '../core/hex.dart';

/// Contract for [StunTransactionTable] entries: when the request went out,
/// used for TTL pruning.
abstract interface class StunPendingRequest {
  DateTime get sentAt;
}

/// Map of outstanding STUN requests keyed by normalized transaction id.
final class StunTransactionTable<T extends StunPendingRequest> {
  /// When set, entries older than [ttl] are pruned on every [insert] —
  /// per RFC 8489 §6.2.1 the total retransmit budget is RTO × (2^Rc − 1),
  /// so anything older can no longer receive a legitimate response.
  StunTransactionTable({this.ttl});

  final Duration? ttl;
  final Map<String, T> _pending = {};

  /// Normalized (lowercase hex) map key for a transaction id.
  static String keyOf(Uint8List txId) => hex(txId);

  /// Register an outstanding request, pruning expired entries first when
  /// a [ttl] is configured.
  void insert(Uint8List txId, T entry) {
    final ttl = this.ttl;
    if (ttl != null && _pending.isNotEmpty) {
      final cutoff = DateTime.now().subtract(ttl);
      _pending.removeWhere((_, e) => e.sentAt.isBefore(cutoff));
    }
    _pending[keyOf(txId)] = entry;
  }

  T? lookup(Uint8List txId) => _pending[keyOf(txId)];

  bool contains(Uint8List txId) => _pending.containsKey(keyOf(txId));

  /// Remove and return the entry for [txId] (null when absent).
  T? take(Uint8List txId) => _pending.remove(keyOf(txId));

  /// [take] by an already-normalized key (from [keyOf] / [keys]).
  T? takeKey(String key) => _pending.remove(key);

  T? operator [](String key) => _pending[key];

  /// Snapshot of the normalized keys — safe to remove entries while
  /// iterating (the retransmit-loop pattern).
  List<String> get keys => _pending.keys.toList();

  Iterable<T> get values => _pending.values;
  bool get isEmpty => _pending.isEmpty;
  bool get isNotEmpty => _pending.isNotEmpty;
  void clear() => _pending.clear();
}
