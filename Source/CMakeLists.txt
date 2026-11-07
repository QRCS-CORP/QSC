#[=[
/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */
]=]

cmake_minimum_required(VERSION 3.21)
project(QSC VERSION 1.4.0.0 LANGUAGES C)

# Root-level entry point; keep the native QSC and QSCTest projects untouched.
set(QSC_LIBRARY_DIR "${PROJECT_SOURCE_DIR}/QSC" CACHE PATH "QSC cryptographic library source directory")
if(NOT EXISTS "${QSC_LIBRARY_DIR}/qsccommon.h")
    if(EXISTS "${PROJECT_SOURCE_DIR}/Source/QSC/qsccommon.h")
        set(QSC_LIBRARY_DIR "${PROJECT_SOURCE_DIR}/Source/QSC" CACHE PATH "QSC cryptographic library source directory" FORCE)
    else()
        message(FATAL_ERROR "Cannot locate QSC/qsccommon.h; set QSC_LIBRARY_DIR explicitly")
    endif()
endif()
if(NOT EXISTS "${QSC_LIBRARY_DIR}/QSC.vcxproj")
    message(FATAL_ERROR "QSC_LIBRARY_DIR does not contain QSC.vcxproj: ${QSC_LIBRARY_DIR}")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(QSC_BUILD_SHARED "Build QSC shared libraries (DLL/SO/DYLIB)" OFF)
if(QSC_BUILD_SHARED OR BUILD_SHARED_LIBS)
    set(QSC_LIBRARY_KIND SHARED)
    set(QSC_JSON_SHARED_LIBRARY true)
else()
    set(QSC_LIBRARY_KIND STATIC)
    set(QSC_JSON_SHARED_LIBRARY false)
endif()
if(MSVC)
    if(QSC_LIBRARY_KIND STREQUAL "SHARED")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    else()
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
endif()
set(QSC_PROFILE "FULL" CACHE STRING "QSC application compilation profile")
set(QSC_CUSTOM_ALGORITHMS "" CACHE STRING "CUSTOM algorithm IDs separated by semicolons or commas")
option(QSC_ENABLE_HARDWARE "Compile optional native hardware providers" OFF)
set(QSC_HARDWARE_PROVIDERS "" CACHE STRING "Hardware providers, comma-separated")
set(QSC_PSA_INCLUDE_DIR "" CACHE PATH "Native PSA include directory")
set(QSC_PSA_LIBRARY "" CACHE FILEPATH "Native PSA Crypto library")
option(QSC_VALIDATE_INVENTORY "Check CMake source list against QSC.vcxproj" ON)
option(QSC_INSTALL_SDK "Install QSC SDK and CMake package" ON)
option(QSC_BUILD_PROFILE_TESTS "Build separate QSC profile smoke tests" OFF)

include("${PROJECT_SOURCE_DIR}/cmake/QSCSources.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/QSCProfiles.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/QSCHardware.cmake")
include("${PROJECT_SOURCE_DIR}/cmake/QSCCompiler.cmake")
if(QSC_VALIDATE_INVENTORY)
    qsc_validate_source_inventory()
endif()
qsc_resolve_profile("${QSC_PROFILE}" QSC_SELECTED_SOURCES QSC_SELECTED_ALGORITHMS)
qsc_resolve_hardware(QSC_PROVIDER_SOURCES QSC_PROVIDER_DEFINITIONS QSC_PROVIDER_LIBRARIES)
list(APPEND QSC_SELECTED_SOURCES ${QSC_PROVIDER_SOURCES})
list(REMOVE_DUPLICATES QSC_SELECTED_SOURCES)
set(QSC_SELECTED_FULL_PATHS "")
foreach(_file IN LISTS QSC_SELECTED_SOURCES)
    list(APPEND QSC_SELECTED_FULL_PATHS "${QSC_LIBRARY_DIR}/${_file}")
endforeach()
add_library(qsc ${QSC_LIBRARY_KIND} ${QSC_SELECTED_FULL_PATHS})
add_library(QSC::QSC ALIAS qsc)
set_target_properties(qsc PROPERTIES OUTPUT_NAME qsc EXPORT_NAME QSC)
if(QSC_LIBRARY_KIND STREQUAL "SHARED")
    set_target_properties(qsc PROPERTIES VERSION "${PROJECT_VERSION}" SOVERSION "${PROJECT_VERSION_MAJOR}")
    if(WIN32)
        # QSC_EXPORT_API already provides the import/export annotations.
        target_compile_definitions(qsc PRIVATE QSC_DLL_API)
        target_compile_definitions(qsc INTERFACE QSC_DLL_API QSC_DLL_IMPORT)
    endif()
endif()
target_include_directories(qsc PUBLIC
    "$<BUILD_INTERFACE:${QSC_LIBRARY_DIR}>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>"
    "$<INSTALL_INTERFACE:include/qsc>")
if(QSC_PROVIDER_DEFINITIONS)
    target_compile_definitions(qsc PUBLIC ${QSC_PROVIDER_DEFINITIONS})
endif()
if("QSC_HARDWARE_PSA_NATIVE_ENABLED" IN_LIST QSC_PROVIDER_DEFINITIONS)
    target_include_directories(qsc PRIVATE "${QSC_PSA_INCLUDE_DIR}")
endif()
find_package(Threads REQUIRED)
target_link_libraries(qsc PUBLIC Threads::Threads "${CMAKE_DL_LIBS}" ${QSC_PROVIDER_LIBRARIES})
if(WIN32)
    target_link_libraries(qsc PUBLIC ws2_32 iphlpapi bcrypt crypt32 advapi32 user32 shlwapi netapi32 psapi)
elseif(UNIX AND NOT APPLE)
    target_link_libraries(qsc PUBLIC m)
endif()
qsc_apply_compiler_options(qsc)
if(QSC_LIBRARY_KIND STREQUAL "SHARED" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(qsc PRIVATE "LINKER:--no-undefined")
endif()

string(REPLACE ";" "," QSC_MANIFEST_ALGORITHMS "${QSC_SELECTED_ALGORITHMS}")
string(REPLACE ";" "," QSC_MANIFEST_HARDWARE "${QSC_HARDWARE_PROVIDERS}")
list(LENGTH QSC_SELECTED_SOURCES QSC_SELECTED_SOURCE_COUNT)
if(QSC_ENABLE_HARDWARE)
    set(QSC_FEATURE_HARDWARE 1)
    set(QSC_JSON_HARDWARE_ENABLED true)
else()
    set(QSC_FEATURE_HARDWARE 0)
    set(QSC_JSON_HARDWARE_ENABLED false)
endif()
foreach(_qsc_feature SHA2 SHA3)
    string(TOLOWER "${_qsc_feature}" _name)
    if("${_name}.c" IN_LIST QSC_SELECTED_SOURCES)
        set(QSC_FEATURE_${_qsc_feature} 1)
    else()
        set(QSC_FEATURE_${_qsc_feature} 0)
    endif()
endforeach()
foreach(_qsc_feature X25519 KYBER768 KYBER1024 MLDSA65 MLDSA87)
    if(_qsc_feature STREQUAL "X25519")
        set(_name eddh25519)
    else()
        string(TOLOWER "${_qsc_feature}" _name)
    endif()
    if("${_name}.c" IN_LIST QSC_SELECTED_SOURCES)
        set(QSC_FEATURE_${_qsc_feature} 1)
    else()
        set(QSC_FEATURE_${_qsc_feature} 0)
    endif()
endforeach()
configure_file("${PROJECT_SOURCE_DIR}/cmake/QSCFeatures.h.in" "${PROJECT_BINARY_DIR}/QSCFeatures.h" @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/cmake/QSCCapabilities.json.in" "${PROJECT_BINARY_DIR}/QSCCapabilities.json" @ONLY)

if("QSC_HARDWARE_TPM_ENABLED" IN_LIST QSC_PROVIDER_DEFINITIONS)
    set(QSC_PACKAGE_REQUIRES_TSS ON)
else()
    set(QSC_PACKAGE_REQUIRES_TSS OFF)
endif()
if(QSC_BUILD_PROFILE_TESTS)
    enable_testing()
    include("${PROJECT_SOURCE_DIR}/cmake/QSCTests.cmake")
endif()
if(QSC_INSTALL_SDK)
    include("${PROJECT_SOURCE_DIR}/cmake/QSCInstall.cmake")
endif()
message(STATUS "QSC profile=${QSC_PROFILE} type=${QSC_LIBRARY_KIND} sources=${QSC_SELECTED_SOURCE_COUNT} library=${QSC_LIBRARY_DIR}")
