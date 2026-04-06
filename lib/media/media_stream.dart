/// W3C MediaStream — a collection of MediaStreamTracks.
/// https://www.w3.org/TR/mediacapture-streams/#mediastream
library;

import '../crypto/csprng.dart';
import 'media_stream_track.dart';

/// A stream consisting of zero or more audio and video tracks.
final class MediaStream {
  final String id;
  final List<MediaStreamTrack> _tracks = [];

  MediaStream({String? id}) : id = id ?? Csprng.randomHex(16);

  List<MediaStreamTrack> getAudioTracks() =>
      List.unmodifiable(_tracks.where((t) => t.kind == 'audio'));

  List<MediaStreamTrack> getVideoTracks() =>
      List.unmodifiable(_tracks.where((t) => t.kind == 'video'));

  List<MediaStreamTrack> getTracks() => List.unmodifiable(_tracks);

  void addTrack(MediaStreamTrack track) {
    if (!_tracks.any((t) => t.id == track.id)) {
      _tracks.add(track);
    }
  }

  void removeTrack(MediaStreamTrack track) {
    _tracks.removeWhere((t) => t.id == track.id);
  }

  MediaStreamTrack? getTrackById(String trackId) {
    for (final t in _tracks) {
      if (t.id == trackId) return t;
    }
    return null;
  }
}
