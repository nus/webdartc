# AGENTS.md

General repo guidance lives in `README.md`, `dart/README.md`, and `CLAUDE.md`.
Per-package standard commands (analyze/test/run) are documented there and in
`.github/workflows/ci.yaml` — prefer those sources over duplicating here.

## Cursor Cloud specific instructions

### Layout note (important)
`CLAUDE.md` refers to the packages as `webdartc/` and `webdartc_flutter/`, but on
disk they are the directories `dart/` (package `webdartc`, pure-Dart library —
the core product) and `flutter/` (package `webdartc_flutter`). Run each package's
commands from its own directory.

### Toolchain
- Flutter SDK (stable, bundles the Dart SDK) is installed at `~/flutter` and is
  on `PATH` via `~/.bashrc`. The bundled Dart satisfies the `>= 3.11.0`
  requirement, so use `dart`/`flutter` directly. The repo is a pub workspace:
  run `flutter pub get` (not `dart pub get`) from the repo root to resolve both
  packages at once.

### Native build hook (non-obvious gotcha)
- The first `dart test` (or `dart pub get` with native assets) in `dart/` runs
  `dart/hook/build.dart`, which source-builds BoringSSL (crypto), libopus and
  libvpx via vcpkg (auto-cloned + bootstrapped) and downloads Cisco OpenH264.
  This first run takes several minutes; results are cached under
  `dart/.dart_tool/hooks_runner/shared/webdartc/`, so later runs are fast. If a
  build seems to "hang", it is almost always the vcpkg native build on a cold
  cache — let it finish rather than killing it.
- Default fast unit-test command (matches CI):
  `cd dart && dart test --exclude-tags e2e,coturn`.

### E2E / browser tests
- `cd dart && dart test test/e2e/` auto-downloads Chrome-for-Testing into
  `dart/.local/chrome_for_testing/` (cached) and drives it via WebDriver — no
  manual browser install needed. `coturn`-tagged TURN tests need `coturn`
  installed and are excluded by default.

### Running the product (manual demo)
- The browser-receiver demo is a good end-to-end smoke test of the WebRTC stack:
  `cd dart && dart run example/video_sender/server.dart --port=8080 --codec=vp8`,
  then open `http://127.0.0.1:8080` in Chrome — the page negotiates a real
  ICE/DTLS/SRTP/RTP connection and the Dart peer streams live video to it.
