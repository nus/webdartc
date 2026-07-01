/// Splits an arbitrarily-chunked s16-interleaved PCM stream into fixed-size
/// (20 ms) frames for an Opus encoder, buffering the sub-frame remainder across
/// calls and stamping each frame with a continuous presentation timestamp.
///
/// Codec-agnostic: it only slices and times frames — what to *do* with each
/// frame (libopus `opus_encode` or MediaCodec) is the caller's `onFrame`. Shared
/// by [OpusEncoderBackend] (libopus) and the MediaCodec Opus encoder backend so
/// the framing/PTS math lives in one place.
library;

import 'dart:typed_data';

/// Called for each complete frame: the samples live in [src] starting at
/// [offset] (length = the configured all-channels frame size), to be encoded
/// with presentation timestamp [ptsUs].
typedef OpusFrameSink = void Function(Int16List src, int offset, int ptsUs);

final class OpusPcmFramer {
  final int _samplesPerFrameAllChannels;
  final int _frameDurationUs;

  // Carry-over for samples not yet aligned to a full frame.
  final Int16List _residue;
  int _residueFill = 0;

  // Timestamp for the next emitted frame — seeded from the first chunk, then
  // advanced one frame at a time (independently of the input chunking) so the
  // RTP timeline stays continuous.
  int? _baseTimestampUs;

  OpusPcmFramer({
    required int samplesPerFrameAllChannels,
    required int frameDurationUs,
  })  : _samplesPerFrameAllChannels = samplesPerFrameAllChannels,
        _frameDurationUs = frameDurationUs,
        _residue = Int16List(samplesPerFrameAllChannels);

  /// Feeds [view] (s16 interleaved), invoking [onFrame] for each complete frame
  /// now available; [firstTimestampUs] seeds the PTS on the very first frame.
  void add(Int16List view, int firstTimestampUs, OpusFrameSink onFrame) {
    _baseTimestampUs ??= firstTimestampUs;
    var pos = 0;

    // Top up the residue and emit one frame if we now have enough.
    if (_residueFill > 0) {
      final need = _samplesPerFrameAllChannels - _residueFill;
      final available = view.length - pos;
      if (available < need) {
        _residue.setRange(_residueFill, _residueFill + available, view, pos);
        _residueFill += available;
        return;
      }
      _residue.setRange(_residueFill, _samplesPerFrameAllChannels, view, pos);
      pos += need;
      _residueFill = 0;
      onFrame(_residue, 0, _nextPts());
    }

    // Drain whole frames straight from the input view (zero-copy slicing).
    while (view.length - pos >= _samplesPerFrameAllChannels) {
      onFrame(view, pos, _nextPts());
      pos += _samplesPerFrameAllChannels;
    }

    // Stash the remainder for the next call.
    final remaining = view.length - pos;
    if (remaining > 0) {
      _residue.setRange(0, remaining, view, pos);
      _residueFill = remaining;
    }
  }

  int _nextPts() {
    final ts = _baseTimestampUs!;
    _baseTimestampUs = ts + _frameDurationUs;
    return ts;
  }

  /// Drops any buffered remainder and resets the PTS seed.
  void reset() {
    _residueFill = 0;
    _baseTimestampUs = null;
  }
}
