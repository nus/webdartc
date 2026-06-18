# Overlay triplet for webdartc's macOS codec builds (libvpx / libopus).
#
# Identical to vcpkg's built-in arm64-osx triplet (static library linkage),
# plus VCPKG_OSX_DEPLOYMENT_TARGET pinned to 10.15. The deployment target can
# only be set through a triplet variable — not an env var — so an overlay
# triplet is required. Keeping it at 10.15 matches the value dart/hook/build.dart
# uses elsewhere and keeps the vendored .a's Mach-O minimum no newer than the
# webdartc_vp8/vp9/codecs wrapper dylib, avoiding ld64's "object file was built
# for newer macOS version than being linked" warning.
#
# Overlay triplets replace (not merge with) the built-in, so every setting the
# built-in arm64-osx defines is repeated here.
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES arm64)
set(VCPKG_OSX_DEPLOYMENT_TARGET 10.15)
