/// Flutter integration layer for webdartc.
///
/// Responsibilities that require Flutter (Texture/GL/Metal context, platform
/// channels for camera UI, etc.):
///   - Video rendering Widget (GLES/Metal shader-based YUV → RGB)
///   - Zero-copy GPU surface renderers (optional, per-platform)
///
/// Responsibilities that do *not* require Flutter and live in the core
/// `webdartc` package:
///   - Codec backends (VP8 via libvpx FFI, future H.264/Opus via FFI)
///   - OS capture/playback via FFI (V4L2, ALSA, etc.)
///   - Fake/test media sources (`FakeVideoSource`, ...)
library;
