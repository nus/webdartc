/// Shared state machine behind the four W3C WebCodecs frontends
/// (`VideoEncoder` / `VideoDecoder` / `AudioEncoder` / `AudioDecoder`).
///
/// Internal — not exported by the package barrel. The public frontends stay
/// thin typed wrappers delegating to [CodecFrontendCore] so their W3C names
/// and signatures are untouched.
library;

// ── Codec state ─────────────────────────────────────────────────────────────

enum CodecState { unconfigured, configured, closed }

// ── Backend lifecycle ───────────────────────────────────────────────────────

/// Lifecycle members every codec backend shares, letting
/// [CodecFrontendCore] drive any of the four backend interfaces.
abstract interface class CodecBackend {
  Future<void> flush();
  void reset();
  void close();
}

// ── Frontend core ───────────────────────────────────────────────────────────

/// The `configure`/`flush`/`reset`/`close` [CodecState] machine common to all
/// four WebCodecs frontends. [label] ('Encoder' / 'Decoder') only flavors the
/// StateError messages.
final class CodecFrontendCore<Backend extends CodecBackend> {
  CodecFrontendCore(this._label);

  final String _label;
  Backend? _backend;
  CodecState _state = CodecState.unconfigured;

  CodecState get state => _state;

  /// Creates the backend via [create] (called with [codec]; throws
  /// [UnsupportedError] naming [codec] when it returns null), wires it up
  /// via [initialize], and enters [CodecState.configured].
  void configure(String codec, Backend? Function(String codec) create,
      void Function(Backend backend) initialize) {
    if (_state == CodecState.closed) throw StateError('$_label is closed');
    _backend = create(codec);
    if (_backend == null) throw UnsupportedError('No backend for codec: $codec');
    initialize(_backend!);
    _state = CodecState.configured;
  }

  /// The configured backend — the encode/decode entry point.
  Backend get backend {
    if (_state != CodecState.configured) throw StateError('$_label not configured');
    return _backend!;
  }

  Future<void> flush() async {
    if (_state != CodecState.configured) return;
    await _backend!.flush();
  }

  void reset() {
    if (_state == CodecState.closed) return;
    _backend?.reset();
    _state = CodecState.unconfigured;
  }

  void close() {
    if (_state == CodecState.closed) return;
    _backend?.close();
    _state = CodecState.closed;
  }
}
