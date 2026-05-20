# The Flutter tooling requires that developers have a version of Visual Studio
# installed that includes CMake 3.14 or later. You should not increase this
# version, as doing so will cause the plugin to fail to compile for some
# customers of the plugin.
cmake_minimum_required(VERSION 3.14)

# Project-level configuration.
set(PROJECT_NAME "webdartc_flutter")
project(${PROJECT_NAME} LANGUAGES CXX)

# Explicitly opt in to modern CMake behaviors to avoid warnings with recent
# versions of CMake.
cmake_policy(VERSION 3.14...3.25)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "webdartc_flutter_plugin")

# Any new source files that you add to the plugin should be added here.
list(APPEND PLUGIN_SOURCES
  "webdartc_flutter_plugin.cpp"
  "webdartc_flutter_plugin.h"
)

# Define the plugin library target. Its name must not be changed (see comment
# on PLUGIN_NAME above).
add_library(${PLUGIN_NAME} SHARED
  "include/webdartc_flutter/webdartc_flutter_plugin_c_api.h"
  "webdartc_flutter_plugin_c_api.cpp"
  ${PLUGIN_SOURCES}
)

# Apply a standard set of build settings that are configured in the
# application-level CMakeLists.txt. This can be removed for plugins that want
# full control over build settings.
apply_standard_settings(${PLUGIN_NAME})

# Symbols are hidden by default to reduce the chance of accidental conflicts
# between plugins. This should not be removed; any symbols that should be
# exported should be explicitly exported with the FLUTTER_PLUGIN_EXPORT macro.
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

# Source include directories and library dependencies. Add any plugin-specific
# dependencies here.
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin)

# Source / runtime encoding is UTF-8; force MSVC to honour it instead of
# the OEM codepage (Shift-JIS on Japanese installs), otherwise non-ASCII
# comments in the plugin / standard library trip C4819 and the standard
# `treat warnings as errors` setting fails the build.
if (MSVC)
  target_compile_options(${PLUGIN_NAME} PRIVATE /utf-8)
endif()

# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(webdartc_flutter_bundled_libraries
  ""
  PARENT_SCOPE
)

# === Tests ===
# `include_${PROJECT_NAME}_tests` is set by the example app's build so unit
# tests only run when building from the example, not when end-user apps
# consume the plugin.
if (${include_${PROJECT_NAME}_tests})
  set(TEST_RUNNER "${PROJECT_NAME}_test")
  enable_testing()

  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/release-1.11.0.zip
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of googletest" FORCE)
  # googletest 1.11.0's own CMakeLists declares `cmake_minimum_required` at
  # < 3.10, which CMake 3.27+ flags as a deprecation. Mute the deprecation
  # warning around the populate step — we don't own the upstream file.
  set(_gtest_prev_warn_deprecated ${CMAKE_WARN_DEPRECATED})
  set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  set(CMAKE_WARN_DEPRECATED ${_gtest_prev_warn_deprecated} CACHE BOOL "" FORCE)
  unset(_gtest_prev_warn_deprecated)

  add_executable(${TEST_RUNNER}
    test/convert_i420_to_bgra8_test.cpp
    ${PLUGIN_SOURCES}
  )
  apply_standard_settings(${TEST_RUNNER})
  target_include_directories(${TEST_RUNNER} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(${TEST_RUNNER} PRIVATE flutter_wrapper_plugin)
  target_link_libraries(${TEST_RUNNER} PRIVATE gtest_main)
  if (MSVC)
    target_compile_options(${TEST_RUNNER} PRIVATE /utf-8)
  endif()
  add_custom_command(TARGET ${TEST_RUNNER} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${FLUTTER_LIBRARY}" $<TARGET_FILE_DIR:${TEST_RUNNER}>
  )

  include(GoogleTest)
  gtest_discover_tests(${TEST_RUNNER})
endif()

