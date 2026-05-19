// Shared env builder for build_libopus_wrappers.dart and
// build_libvpx_wrappers.dart. Self-contained (only `dart:io`) so the
// callers still work without `dart pub get`.

import 'dart:io';

/// Builds the env to hand to `Process.start(environment: ...)` for the
/// vcpkg / cl invocations.
///
/// Two concerns are handled here:
///
///   - `package:hooks_runner` scrubs many Windows env vars from the
///     build-hook environment for reproducibility, but vcpkg needs
///     APPDATA / LOCALAPPDATA for its state dir and ProgramFiles /
///     ProgramFiles(x86) for vswhere-based VS detection. Synthesise the
///     missing ones from USERPROFILE / SystemDrive (which the runner
///     does pass through).
///
///   - Windows env names are case-insensitive, but the GitHub Actions
///     Windows runner image's env block carries `ProgramW6432` and
///     `PROGRAMW6432` as separate entries. Forwarding both via
///     `Process.start` crashes MSBuild's case-sensitive .NET
///     `StringDictionary` with "Item has already been added. Key in
///     dictionary: 'PROGRAMW6432'". Collapse case-duplicates here,
///     keeping the first-seen original case.
Map<String, String> buildWrapperChildEnv() {
  if (!Platform.isWindows) {
    return Map<String, String>.from(Platform.environment);
  }
  final byLower = <String, String>{};
  final env = <String, String>{};
  for (final e in Platform.environment.entries) {
    final lk = e.key.toLowerCase();
    if (byLower.containsKey(lk)) continue;
    byLower[lk] = e.key;
    env[e.key] = e.value;
  }
  String? getCi(String k) {
    final orig = byLower[k.toLowerCase()];
    return orig == null ? null : env[orig];
  }
  void putIfMissingCi(String k, String v) {
    final lk = k.toLowerCase();
    if (byLower.containsKey(lk)) return;
    byLower[lk] = k;
    env[k] = v;
  }
  final userProfile = getCi('USERPROFILE') ?? r'C:\Users\Default';
  final systemDrive = getCi('SystemDrive') ?? userProfile.substring(0, 2);
  putIfMissingCi('APPDATA', '$userProfile\\AppData\\Roaming');
  putIfMissingCi('LOCALAPPDATA', '$userProfile\\AppData\\Local');
  putIfMissingCi('ProgramFiles', '$systemDrive\\Program Files');
  putIfMissingCi('ProgramW6432', '$systemDrive\\Program Files');
  putIfMissingCi('ProgramFiles(x86)', '$systemDrive\\Program Files (x86)');
  return env;
}
