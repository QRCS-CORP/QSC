cmake_minimum_required(VERSION 3.15)

# ─── Project ───────────────────────────────────────────────────────────────────
project(QSC
        VERSION 1.0.0            # update when you tag new releases
        DESCRIPTION "Quantum-Secure Cryptographic Library"
        LANGUAGES C)

# ─── Options ───────────────────────────────────────────────────────────────────
option(BUILD_SHARED_LIBS "Build shared instead of static library" OFF)
option(QSC_ENABLE_TESTS  "Enable unit tests (adds tests/ dir when available)" OFF)
option(QSC_STRICT_WARNINGS "Turn on strict compiler warnings" ON)

# ─── Build Type ────────────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ─── Compiler Settings ─────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(QSC_STRICT_WARNINGS)
  if(MSVC)
    add_compile_options(/W4)
  else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
  endif()
endif()

# ─── Source & Include Paths ────────────────────────────────────────────────────
set(QSC_SOURCE_DIR   ${PROJECT_SOURCE_DIR}/Source/QSC)
file(GLOB_RECURSE QSC_SRC CONFIGURE_DEPENDS
     "${QSC_SOURCE_DIR}/*.c"
     "${QSC_SOURCE_DIR}/*.h")

add_library(qsc ${QSC_SRC})
target_include_directories(qsc PUBLIC ${QSC_SOURCE_DIR})

# OS-specific macro (optional)
if(WIN32)
  target_compile_definitions(qsc PRIVATE QSC_WINDOWS)
elseif(UNIX)
  target_compile_definitions(qsc PRIVATE QSC_LINUX)
endif()

# ─── Install Rules ─────────────────────────────────────────────────────────────
include(GNUInstallDirs)

install(TARGETS qsc
        EXPORT qscTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(DIRECTORY ${QSC_SOURCE_DIR}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qsc
        FILES_MATCHING PATTERN "*.h")

# ─── Config Package File  (so “find_package(qsc CONFIG)” works) ────────────────
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/qscConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion)

export(EXPORT qscTargets
       FILE "${PROJECT_BINARY_DIR}/qscTargets.cmake"
       NAMESPACE qsc::)

configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/qscConfig.cmake.in"
    "${PROJECT_BINARY_DIR}/qscConfig.cmake"
    @ONLY)

install(EXPORT qscTargets
        FILE qscTargets.cmake
        NAMESPACE qsc::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qsc)

install(FILES
        "${PROJECT_BINARY_DIR}/qscConfig.cmake"
        "${PROJECT_BINARY_DIR}/qscConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qsc)

# ─── Tests (optional) ──────────────────────────────────────────────────────────
if(QSC_ENABLE_TESTS)
  enable_testing()
  add_subdirectory(tests)  # add tests/ later
endif()
