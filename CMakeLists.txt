# ------------------------------------------------------------------------------
#  QSC Cryptographic Library - CMake build script
# ------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

project(
    QSC
    VERSION 1.0.0
    DESCRIPTION "Quantum-Secure Cryptographic Library"
    LANGUAGES C
)

# --- Options -----------------------------------------------------------------
option(BUILD_SHARED_LIBS   "Build shared instead of static library" OFF)
option(QSC_ENABLE_TESTS    "Enable unit tests if tests/ exists"     OFF)
option(QSC_ENABLE_QSCTEST  "Build the QSCTest executable"           OFF)
option(QSC_STRICT_WARNINGS "Turn on pedantic compiler warnings"     ON)

# --- Build-type default -------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# --- Compiler & policy settings ----------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

# --- Warning flags ------------------------------------------------------------
if(QSC_STRICT_WARNINGS)
  if(MSVC)
    add_compile_options(/W4 /WX)
  elseif(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    add_compile_options(
      -Wall
      -Wextra
      -Wpedantic
      -Wno-unused-parameter
      -Wno-unused-function
      -Wno-cast-function-type
      -Wno-sign-compare
    )
  endif()
endif()

# --- Source collection --------------------------------------------------------
set(QSC_SOURCE_DIR "${PROJECT_SOURCE_DIR}/Source/QSC")

file(GLOB_RECURSE QSC_SOURCES CONFIGURE_DEPENDS
  "${QSC_SOURCE_DIR}/*.c"
  "${QSC_SOURCE_DIR}/*.h"
)

# Remove Intel-specific NASM wrapper sources on non-x86 targets
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i[3-6]86)$")
  list(FILTER QSC_SOURCES EXCLUDE REGEX ".*/NASM/.*\\.c$")
endif()

add_library(qsc ${QSC_SOURCES})
add_library(qsc::qsc ALIAS qsc)

# Public headers: build interface vs install interface
target_include_directories(qsc
  PUBLIC
    $<BUILD_INTERFACE:${QSC_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/qsc>
)

# OS-specific compile definitions
if(WIN32)
  target_compile_definitions(qsc PRIVATE QSC_WINDOWS)
elseif(APPLE)
  target_compile_definitions(qsc PRIVATE QSC_MACOS)
elseif(UNIX)
  target_compile_definitions(qsc PRIVATE QSC_LINUX)
endif()

# --- Optional tests -----------------------------------------------------------
if(QSC_ENABLE_TESTS AND EXISTS "${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt")
  enable_testing()
  add_subdirectory(tests)
endif()

# --- QSCTest (demo / verification) -------------------------------------------
if(QSC_ENABLE_QSCTEST)
  set(QSCTEST_DIR "${PROJECT_SOURCE_DIR}/Source/QSCTest")

  file(GLOB QSCTEST_SOURCES CONFIGURE_DEPENDS
    "${QSCTEST_DIR}/*.c"
    "${QSCTEST_DIR}/*.h"
  )

  if(QSCTEST_SOURCES)
    add_executable(qsctest ${QSCTEST_SOURCES})
    target_link_libraries(qsctest PRIVATE qsc)
    target_include_directories(qsctest PRIVATE "${QSCTEST_DIR}" "${QSC_SOURCE_DIR}")

    enable_testing()
    add_test(NAME QSCTest COMMAND qsctest)

    message(STATUS "QSCTest enabled - executable target 'qsctest' added")
  else()
    message(WARNING "QSC_ENABLE_QSCTEST is ON but no sources found in ${QSCTEST_DIR}")
  endif()
endif()

# --- Install rules ------------------------------------------------------------
include(GNUInstallDirs)

install(
  TARGETS qsc
  EXPORT qscTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
  DIRECTORY "${QSC_SOURCE_DIR}/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/qsc"
  FILES_MATCHING PATTERN "*.h"
)

# --- Config package generation (for find_package) -----------------------------
include(CMakePackageConfigHelpers)

install(
  EXPORT qscTargets
  FILE qscTargets.cmake
  NAMESPACE qsc::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/qsc"
)

if(EXISTS "${PROJECT_SOURCE_DIR}/cmake/qscConfig.cmake.in")
  write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/qscConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
  )

  configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/qscConfig.cmake.in"
    "${PROJECT_BINARY_DIR}/qscConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/qsc"
    NO_CHECK_REQUIRED_COMPONENTS_MACRO
  )

  install(
    FILES
      "${PROJECT_BINARY_DIR}/qscConfig.cmake"
      "${PROJECT_BINARY_DIR}/qscConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/qsc"
  )
else()
  message(STATUS "Skipping qsc package config generation: cmake/qscConfig.cmake.in not found")
endif()

# --- Summary ------------------------------------------------------------------
if(BUILD_SHARED_LIBS)
  set(_qsc_kind "shared")
else()
  set(_qsc_kind "static")
endif()

message(STATUS "QSC built as ${_qsc_kind} library")
message(STATUS "Source path : ${QSC_SOURCE_DIR}")
message(STATUS "Install path: ${CMAKE_INSTALL_PREFIX}")