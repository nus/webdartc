# libvpx vcpkg manifest

`vcpkg.json` pins the upstream libvpx version and the vcpkg registry
baseline. `dart/hook/build.dart` consumes it to source-build the static
libvpx archive that the `webdartc_vp8` / `webdartc_vp9` wrappers link
against:

* **macOS** — `vcpkg install --triplet=arm64-osx|x64-osx` directly in the
  build hook (`_vcpkgBuildLibvpx`), with the overlay triplets in
  `dart/tool/vcpkg_triplets/` pinning the deployment target.
* **Windows** — `dart/tool/build_libvpx_wrappers.dart` installs libvpx
  here, then compiles `webdartc_vp{8,9}.dll` with MSVC.

Linux / Android instead build the bundled `third_party/libvpx` submodule.

To bump libvpx: edit the `libvpx` version (`overrides`) and the
`builtin-baseline` in `vcpkg.json`. The CI build-hook artifact cache key
hashes this file, so a bump invalidates the cache and triggers a rebuild.
