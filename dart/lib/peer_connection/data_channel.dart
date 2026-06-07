// ignore_for_file: unused_element
part of 'peer_connection.dart';

/// Data channel (W3C RTCDataChannel without "RTC" prefix).
///
/// Maps to the W3C RTCDataChannel interface.
final class DataChannel {
  final String label;
  final bool ordered;
  final int? maxRetransmitTime;
  final int? maxRetransmits;
  final String protocol;
  final bool negotiated;
  final int id;

  DataChannelState _readyState = DataChannelState.connecting;

  /// Monotonic counters reported via `PeerConnection.getStats()`. The
  /// "messages" count is one per `send`/`sendBinary` call; "bytes" is
  /// the payload size handed to / received from the application
  /// (post-SCTP demux, no DCEP/SCTP framing overhead).
  int get messagesSent => _messagesSent;
  int get bytesSent => _bytesSent;
  int get messagesReceived => _messagesReceived;
  int get bytesReceived => _bytesReceived;
  int _messagesSent = 0;
  int _bytesSent = 0;
  int _messagesReceived = 0;
  int _bytesReceived = 0;

  final _messageController = StreamController<DataChannelMessageEvent>.broadcast();
  final _openController = StreamController<void>.broadcast();
  final _closingController = StreamController<void>.broadcast();
  final _closeController = StreamController<void>.broadcast();
  final _errorController = StreamController<Object>.broadcast();

  // Callback set by PeerConnection to send data via SCTP.
  void Function(Uint8List data, {bool binary})? _sendCallback;

  // Callback set by PeerConnection to initiate an SCTP stream reset when the
  // channel is closed (RFC 8831 §6.7). Null until wired or when there is no
  // association to reset.
  void Function()? _closeCallback;

  DataChannel({
    required this.label,
    this.ordered = true,
    this.maxRetransmitTime,
    this.maxRetransmits,
    this.protocol = '',
    this.negotiated = false,
    required this.id,
  });

  DataChannelState get readyState => _readyState;

  /// Stream of incoming messages.
  Stream<DataChannelMessageEvent> get onMessage => _messageController.stream;

  /// Fired when the channel opens.
  Stream<void> get onOpen => _openController.stream;

  /// Fired when the channel begins closing (W3C `onclosing`) — i.e. the SCTP
  /// stream reset has been initiated but not yet completed.
  Stream<void> get onClosing => _closingController.stream;

  /// Fired when the channel closes.
  Stream<void> get onClose => _closeController.stream;

  /// Fired on errors.
  Stream<Object> get onError => _errorController.stream;

  /// Send a string message. Encoded as UTF-8 per RFC 8831 §6.6 — sending
  /// the UTF-16 code units would corrupt any non-ASCII text on the wire.
  void send(String data) {
    _assertOpen();
    final bytes = utf8.encode(data);
    _sendCallback?.call(bytes, binary: false);
    _messagesSent++;
    _bytesSent += bytes.length;
  }

  /// Send binary data.
  void sendBinary(Uint8List data) {
    _assertOpen();
    _sendCallback?.call(data, binary: true);
    _messagesSent++;
    _bytesSent += data.length;
  }

  /// Begin closing the channel (W3C close procedure). Transitions to
  /// `closing`, fires `onClosing`, and initiates the SCTP stream reset
  /// (RFC 8831 §6.7). The transition to `closed` (and `onClose`) happens in
  /// [_finalizeClose] once the reset completes. With no association to reset
  /// (e.g. SCTP not established) it closes immediately.
  void close() {
    if (_readyState == DataChannelState.closed ||
        _readyState == DataChannelState.closing) {
      return;
    }
    _readyState = DataChannelState.closing;
    _closingController.add(null);
    final cb = _closeCallback;
    if (cb != null) {
      cb();
    } else {
      _finalizeClose();
    }
  }

  /// Complete the close once the SCTP stream reset finishes. Idempotent.
  void _finalizeClose() {
    if (_readyState == DataChannelState.closed) return;
    _readyState = DataChannelState.closed;
    _closeController.add(null);
    _disposeControllers();
  }

  void _assertOpen() {
    if (_readyState != DataChannelState.open) {
      throw StateError('DataChannel: not open (state=$_readyState)');
    }
  }

  // ── Internal (called by PeerConnection) ──────────────────────────────────

  void _open() {
    _readyState = DataChannelState.open;
    _openController.add(null);
  }

  void _deliverMessage(Uint8List data, bool isBinary) {
    if (_readyState != DataChannelState.open) return;
    _messagesReceived++;
    _bytesReceived += data.length;
    _messageController.add(DataChannelMessageEvent(data: data, isBinary: isBinary));
  }

  void _disposeControllers() {
    _messageController.close();
    _openController.close();
    _closingController.close();
    _closeController.close();
    _errorController.close();
  }
}

enum DataChannelState { connecting, open, closing, closed }

final class DataChannelMessageEvent {
  final Uint8List data;
  final bool isBinary;

  const DataChannelMessageEvent({required this.data, required this.isBinary});

  /// The payload decoded as UTF-8 (RFC 8831 §6.6). Malformed sequences are
  /// replaced with U+FFFD rather than throwing, so a non-conformant peer
  /// can't crash a `text` read.
  String get text => utf8.decode(data, allowMalformed: true);
}

/// Options for creating a data channel.
final class DataChannelInit {
  final bool ordered;
  final int? maxPacketLifeTime;
  final int? maxRetransmits;
  final String protocol;
  final bool negotiated;
  final int? id;

  const DataChannelInit({
    this.ordered = true,
    this.maxPacketLifeTime,
    this.maxRetransmits,
    this.protocol = '',
    this.negotiated = false,
    this.id,
  });
}
