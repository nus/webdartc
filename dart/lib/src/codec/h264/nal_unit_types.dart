/// H.264 NAL unit types and header fields (ITU-T H.264 §7.4.1; RFC 6184 §5.2).
///
/// Shared by the RTP payload packetizer and the hardware-codec backends so
/// the values are defined once.
abstract final class H264NalType {
  H264NalType._();

  /// Mask for the nal_unit_type bits of the NAL unit header byte.
  static const int mask = 0x1F;

  /// Mask for the F (forbidden_zero_bit) + NRI bits of the NAL unit header.
  static const int fnriMask = 0xE0;

  static const int idr = 5; // IDR (keyframe) slice
  static const int sps = 7; // Sequence parameter set
  static const int pps = 8; // Picture parameter set

  // RTP payload structures (RFC 6184 §5.2).
  static const int stapA = 24; // STAP-A aggregation packet
  static const int fuA = 28; // FU-A fragmentation unit
}
