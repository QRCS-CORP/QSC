cmake_minimum_required(VERSION 3.15)
project(QSC LANGUAGES C)

# Set default to Release build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Use position-independent code for shared libs if required later
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
file(GLOB_RECURSE QSC_SOURCES CONFIGURE_DEPENDS "src/*.c" "src/*.h" "include/*.h")

# Create the static library
add_library(qsc STATIC ${QSC_SOURCES})
target_include_directories(qsc PUBLIC
  ${PROJECT_SOURCE_DIR}/include
)

# OS-specific flags (basic example)
if(WIN32)
  target_compile_definitions(qsc PRIVATE QSC_WINDOWS)
elseif(UNIX)
  target_compile_definitions(qsc PRIVATE QSC_LINUX)
endif()

# Optional: install target
install(TARGETS qsc DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

# Enable tests later (commented for now)
# enable_testing()
# add_subdirectory(tests)
