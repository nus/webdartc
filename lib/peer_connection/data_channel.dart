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

  final _messageController = StreamController<DataChannelMessageEvent>.broadcast();
  final _openController = StreamController<void>.broadcast();
  final _closeController = StreamController<void>.broadcast();
  final _errorController = StreamController<Object>.broadcast();

  // Callback set by PeerConnection to send data via SCTP.
  void Function(Uint8List data, {bool binary})? _sendCallback;

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

  /// Fired when the channel closes.
  Stream<void> get onClose => _closeController.stream;

  /// Fired on errors.
  Stream<Object> get onError => _errorController.stream;

  /// Send a string message.
  void send(String data) {
    _assertOpen();
    _sendCallback?.call(Uint8List.fromList(data.codeUnits), binary: false);
  }

  /// Send binary data.
  void sendBinary(Uint8List data) {
    _assertOpen();
    _sendCallback?.call(data, binary: true);
  }

  void close() {
    if (_readyState == DataChannelState.closed) return;
    _readyState = DataChannelState.closing;
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
    _messageController.add(DataChannelMessageEvent(data: data, isBinary: isBinary));
  }

  void _disposeControllers() {
    _messageController.close();
    _openController.close();
    _closeController.close();
    _errorController.close();
  }
}

enum DataChannelState { connecting, open, closing, closed }

final class DataChannelMessageEvent {
  final Uint8List data;
  final bool isBinary;

  const DataChannelMessageEvent({required this.data, required this.isBinary});

  String get text => String.fromCharCodes(data);
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
