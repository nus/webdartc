# Overlay triplet for webdartc's macOS codec builds (libvpx / libopus).
# See arm64-osx.cmake in this directory for the rationale; this is the x86_64
# counterpart. Mirrors vcpkg's built-in x64-osx triplet plus the pinned
# VCPKG_OSX_DEPLOYMENT_TARGET.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES x86_64)
set(VCPKG_OSX_DEPLOYMENT_TARGET 10.15)
