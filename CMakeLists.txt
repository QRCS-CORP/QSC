cmake_minimum_required(VERSION 3.15)
project(QSC VERSION 1.0.0 LANGUAGES C)

# ---------------------------------------------------------------------------
# Options and policies
# ---------------------------------------------------------------------------
if(POLICY CMP0135)
  # Keep NEW behavior but silence unwanted warnings (optional)
  cmake_policy(SET CMP0135 NEW)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
set(QSC_SOURCE_DIR ${PROJECT_SOURCE_DIR}/Source/QSC)
file(GLOB_RECURSE QSC_SOURCES CONFIGURE_DEPENDS
     "${QSC_SOURCE_DIR}/*.c"
     "${QSC_SOURCE_DIR}/*.h")

add_library(qsc STATIC ${QSC_SOURCES})

target_include_directories(qsc
  PUBLIC
        $<BUILD_INTERFACE:${QSC_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include/qsc>
)

if(WIN32)
  target_compile_definitions(qsc PRIVATE QSC_WINDOWS)
elseif(UNIX)
  target_compile_definitions(qsc PRIVATE QSC_LINUX)
endif()

# ---------------------------------------------------------------------------
# Optional install rules (still work with CMP0135 NEW)
# ---------------------------------------------------------------------------
include(GNUInstallDirs)

install(TARGETS qsc
        EXPORT qscTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(DIRECTORY ${QSC_SOURCE_DIR}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qsc
        FILES_MATCHING PATTERN "*.h")

export(EXPORT qscTargets FILE "${CMAKE_CURRENT_BINARY_DIR}/qscTargets.cmake")
