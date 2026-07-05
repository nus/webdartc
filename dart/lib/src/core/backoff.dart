/// Exponential retransmit backoff: `baseMs * 2^attempt`, clamped to
/// [maxMs]. Consolidates the per-protocol copies (ICE RFC 8445 §14.3,
/// DTLS RFC 6347 §4.2.4.1 / RFC 9147 §5.7, SCTP T3-rtx RFC 4960 §6.3.1);
/// each protocol keeps its own base/cap so retransmit timing is unchanged.
class ExponentialBackoff {
  const ExponentialBackoff({required this.baseMs, required this.maxMs});

  /// Delay before the first retransmit (attempt 0).
  final int baseMs;

  /// Upper clamp on the computed delay.
  final int maxMs;

  /// Delay in milliseconds before retransmit [attempt] (0-based).
  int delayMs(int attempt) => (baseMs * (1 << attempt)).clamp(0, maxMs);
}
