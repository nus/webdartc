/// MediaCodec MIME types — the `AMEDIAFORMAT_KEY_MIME` value that selects a
/// codec component. Shared by the availability probe ([platformCodecAvailable])
/// and the per-codec MediaCodec backends so the string lives in one place.
library;

const String h264Mime = 'video/avc';
const String vp8Mime = 'video/x-vnd.on2.vp8';
