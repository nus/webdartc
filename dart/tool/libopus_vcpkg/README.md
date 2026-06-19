# libopus vcpkg manifest

`vcpkg.json` pins the upstream libopus version and the vcpkg registry
baseline. `dart/hook/build.dart` consumes it to source-build the static
libopus archive that the `webdartc_codecs` (opus) wrapper links against:

* **macOS** — `vcpkg install --triplet=arm64-osx|x64-osx` directly in the
  build hook (`_vcpkgBuildOpus`), with the overlay triplets in
  `dart/tool/vcpkg_triplets/` pinning the deployment target.
* **Windows** — `dart/tool/build_libopus_wrappers.dart` installs libopus
  here, then compiles `webdartc_opus.dll` with MSVC.

Linux / Android instead build the bundled `third_party/opus` submodule.

To bump libopus: edit the `opus` version (`overrides`) and the
`builtin-baseline` in `vcpkg.json`. The CI build-hook artifact cache key
hashes this file, so a bump invalidates the cache and triggers a rebuild.
