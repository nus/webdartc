# libopus vcpkg manifest

`vcpkg.json` pins the upstream libopus version and the vcpkg registry
baseline. Two consumers point at it:

* `.github/workflows/build-libopus-prebuilt.yaml` — produces the
  release-attached prebuilt zips that end users download.
* `dart/hook/build.dart` (Windows source-build opt-in path) — builds
  the same `webdartc_opus.dll` locally when the user sets the
  `libopus_source_build` pubspec define.

Both paths go through `dart/tool/build_libopus_wrappers.dart`, so the
two outputs stay bit-compatible.

See the workflow's `WRAPPER_REVISION` env var for the version-bump
procedure.
