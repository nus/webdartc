/// Per-platform value dispatch.
///
/// One of the few intentional `dart:io` users outside `lib/transport/`
/// (`Platform` inspection only — no I/O). Shared by the crypto backend
/// factories; also the intended home for a future shared native-library
/// loader (see the "Shared dynamic-library loader helper" backlog entry).
library;

import 'dart:io' show Platform;

/// Returns the value for the current platform.
///
/// [posix] covers Linux + Android (they share the BoringSSL crypto backend);
/// macOS is dispatched separately even though it is also POSIX.
///
/// Throws [UnsupportedError] on any other platform.
T forPlatform<T>({
  required T Function() macos,
  required T Function() posix,
  required T Function() windows,
}) {
  if (Platform.isMacOS) return macos();
  if (Platform.isLinux || Platform.isAndroid) return posix();
  if (Platform.isWindows) return windows();
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}
