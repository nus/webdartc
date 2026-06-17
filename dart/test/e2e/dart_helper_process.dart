import 'dart:io';

int _seq = 0;

/// Spawns `dart run <script>` for an e2e helper in a private working directory.
///
/// dartdev re-copies every bundled native code asset (the BoringSSL-backed
/// `libwebdartc_crypto.so`, the codec `.so`/`.dll`s, …) into
/// `$CWD/.dart_tool/lib/` non-atomically on **every** `dart run`. When helpers
/// share a working directory, a newly-spawned helper truncates+rewrites the
/// exact files that already-running helpers have mmap'd — on Linux that
/// SIGBUSes the live process, on Windows it fails the copy (dartbug 59668).
/// Crypto runs per-packet for a helper's whole lifetime, so on the BoringSSL
/// backend the race is near-deterministic rather than a rare flake.
///
/// Giving each helper a unique working directory gives it a private
/// `.dart_tool/lib/`, removing the race entirely. [script] is resolved against
/// the package root (the test runner's CWD) so its absolute path survives the
/// CWD switch; the BoringSSL/codec builds stay cached under the package root's
/// `.dart_tool` and are not rebuilt per helper.
///
/// The private `.dart_tool/lib/` copy is tens of MB of `.so`s, so each helper's
/// working directory is reclaimed once that helper exits.
Future<Process> spawnDartHelper(
  String script,
  List<String> args, {
  Map<String, String>? environment,
}) async {
  final pkgRoot = Directory.current.absolute.path;
  final workDir = Directory('$pkgRoot/.e2e_work/h${_seq++}_$pid')
    ..createSync(recursive: true);
  final proc = await Process.start(
    Platform.resolvedExecutable,
    ['run', '$pkgRoot/$script', ...args],
    workingDirectory: workDir.path,
    environment: environment,
  );
  proc.exitCode.then((_) {
    try {
      workDir.deleteSync(recursive: true);
    } on FileSystemException {
      // Best-effort cleanup; a leftover dir is gitignored and harmless.
    }
  }).ignore();
  return proc;
}
