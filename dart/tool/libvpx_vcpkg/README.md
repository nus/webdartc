# libvpx vcpkg manifest

`vcpkg.json` pins the upstream libvpx version and the vcpkg registry
baseline. Two consumers point at it:

* `.github/workflows/build-libvpx-prebuilt.yaml` — produces the
  release-attached prebuilt zips that end users download.
* `dart/hook/build.dart` (Windows source-build opt-in path) — builds
  the same `webdartc_vp{8,9}.dll` locally when the user sets the
  `libvpx_source_build` pubspec define.

Both paths go through `dart/tool/build_libvpx_wrappers.dart`, so the
two outputs stay bit-compatible.

See the workflow's `WRAPPER_REVISION` env var for the version-bump
procedure.
