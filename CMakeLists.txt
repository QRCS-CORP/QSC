cmake_minimum_required(VERSION 3.15)
project(QSC LANGUAGES C)

# Use C11 and generate position-independent code
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set Release as default build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Source directory
set(QSC_SOURCE_DIR ${PROJECT_SOURCE_DIR}/Source/QSC)

# Collect all .c and .h files from Source/QSC
file(GLOB_RECURSE QSC_SOURCES CONFIGURE_DEPENDS
  "${QSC_SOURCE_DIR}/*.c"
  "${QSC_SOURCE_DIR}/*.h"
)

# Create static library
add_library(qsc STATIC ${QSC_SOURCES})

# Public header include path
target_include_directories(qsc PUBLIC ${QSC_SOURCE_DIR})

# OS-specific macro definitions
if(WIN32)
  target_compile_definitions(qsc PRIVATE QSC_WINDOWS)
elseif(UNIX)
  target_compile_definitions(qsc PRIVATE QSC_LINUX)
endif()
