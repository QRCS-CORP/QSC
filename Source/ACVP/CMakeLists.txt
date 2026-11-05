cmake_minimum_required(VERSION 3.20)
project(QSC_ACVP_Offline LANGUAGES C)

# Isolated qualification build: never changes QSC project settings.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(QSC_ACVP_TLS_CLASS "3" CACHE STRING "Existing QSC TLS parameter class: 1, 3, or 5")
set_property(CACHE QSC_ACVP_TLS_CLASS PROPERTY STRINGS 1 3 5)

if(NOT QSC_ACVP_TLS_CLASS MATCHES "^[135]$")
    message(FATAL_ERROR "QSC_ACVP_TLS_CLASS must be 1, 3, or 5")
endif()

# External QSC dependency is checked out by CI; never modify the QSC repository.
set(QSC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../dependency/QSC/Source" CACHE PATH
    "External QSC Source directory containing QSC and CAVP")
if(NOT EXISTS "${QSC_ROOT}/QSC/aes.c" OR NOT EXISTS "${QSC_ROOT}/CAVP/cavp.c")
    message(FATAL_ERROR "Expected external QSC checkout at ${QSC_ROOT}. Run: git clone https://github.com/QRCS-CORP/QSC.git dependency/QSC")
endif()
file(GLOB QSC_SOURCES CONFIGURE_DEPENDS "${QSC_ROOT}/QSC/*.c")
file(GLOB CAVP_SOURCES CONFIGURE_DEPENDS "${QSC_ROOT}/CAVP/*.c")
# The CI entry point lives in this repository; the upstream CAVP is unchanged.
list(REMOVE_ITEM CAVP_SOURCES "${QSC_ROOT}/CAVP/cavp.c")
list(APPEND CAVP_SOURCES "${CMAKE_CURRENT_LIST_DIR}/cavp_runner.c")

# ECDSA P-384 remains a mandatory member of the complete qualification targets.
# While its generated fixed-base table is being updated, build only the independent
# preliminary targets explicitly. Never silently remove P-384 from the full target.
set(QSC_ACVP_P384_READY TRUE)
# The replacement signer may no longer reference the old generated table.
# Determine readiness from the current source instead of assuming its design.
file(READ "${QSC_ROOT}/QSC/ecdsap384.c" QSC_ACVP_P384_SOURCE)
if(QSC_ACVP_P384_SOURCE MATCHES "#include \"p384_fixed_w6_table[.]h\"" AND
   NOT EXISTS "${QSC_ROOT}/QSC/p384_fixed_w6_table.h")
    set(QSC_ACVP_P384_READY FALSE)
    message(WARNING "ECDSA P-384 source references a missing generated table; complete target remains mandatory")
endif()
if(QSC_ACVP_P384_SOURCE MATCHES "#include \"p384_fixed_w6_solinas_table[.]h\"" AND
   NOT EXISTS "${QSC_ROOT}/QSC/p384_fixed_w6_solinas_table.h")
    # This table is needed only when the experimental generator is selected.
    message(STATUS "P-384 optional Solinas table not present; experimental generator is unavailable")
endif()

if(QSC_ACVP_P384_READY)
    add_library(qsc_acvp_offline STATIC ${QSC_SOURCES})
else()
    add_library(qsc_acvp_offline STATIC EXCLUDE_FROM_ALL ${QSC_SOURCES})
endif()
target_include_directories(qsc_acvp_offline PUBLIC "${QSC_ROOT}/QSC")
target_compile_definitions(qsc_acvp_offline PUBLIC
    QSC_TLS_NO_DEFAULT_SECURITY_CLASS
    QSC_TLS_SECURITY_CLASS_${QSC_ACVP_TLS_CLASS})

# The reference SLH-DSA harness uses the legacy SPHINCS+ API and one SHAKE
# parameter selection per build. Match its selection to the TLS class.
if(QSC_ACVP_TLS_CLASS STREQUAL "1")
    target_compile_definitions(qsc_acvp_offline PUBLIC "QSC_SPHINCSPLUS_S1S128SHAKERS=")
elseif(QSC_ACVP_TLS_CLASS STREQUAL "3")
    target_compile_definitions(qsc_acvp_offline PUBLIC "QSC_SPHINCSPLUS_S3S192SHAKERS=")
else()
    target_compile_definitions(qsc_acvp_offline PUBLIC "QSC_SPHINCSPLUS_S5S256SHAKERS=")
endif()

if(NOT WIN32)
    target_link_libraries(qsc_acvp_offline PUBLIC m pthread)
endif()

if(QSC_ACVP_P384_READY)
    add_executable(qsc_cavp ${CAVP_SOURCES})
else()
    add_executable(qsc_cavp EXCLUDE_FROM_ALL ${CAVP_SOURCES})
endif()
target_include_directories(qsc_cavp PRIVATE "${QSC_ROOT}/CAVP")
target_link_libraries(qsc_cavp PRIVATE qsc_acvp_offline)

# Small shared library for the local SHA vector simulator. Do not link the
# incomplete ECC and TLS graph into an executable or a shared-library image.
add_library(qsc_acvp_hash SHARED
    "${QSC_ROOT}/QSC/pbmac1.c"
    "${QSC_ROOT}/QSC/sha2.c"
    "${QSC_ROOT}/QSC/sha3.c"
    "${QSC_ROOT}/QSC/intutils.c"
    "${QSC_ROOT}/QSC/memutils.c")
target_include_directories(qsc_acvp_hash PRIVATE "${QSC_ROOT}/QSC")
set_target_properties(qsc_acvp_hash PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

# P-384 is always in the complete ECC target. The preliminary target is
# independent of the changing signer and does NOT satisfy full qualification.
set(QSC_ACVP_ECC_SOURCES
    ecdhp256.c ecdhp384.c ecdhp521.c
    ecdsap256.c ecdsap384.c ecdsap521.c
    eddh25519.c eddh448.c eddsa25519.c eddsa448.c
    ed25519.c ed448.c
    donna128.c
    sha2.c sha3.c memutils.c intutils.c
    csp.c cpuidex.c acp.c consoleutils.c stringutils.c sysutils.c rdp.c)
set(QSC_ACVP_ECC_FILES "")
foreach(QSC_ACVP_SOURCE IN LISTS QSC_ACVP_ECC_SOURCES)
    list(APPEND QSC_ACVP_ECC_FILES "${QSC_ROOT}/QSC/${QSC_ACVP_SOURCE}")
endforeach()
if(QSC_ACVP_P384_READY)
    add_library(qsc_acvp_ecc SHARED ${QSC_ACVP_ECC_FILES} "${CMAKE_CURRENT_LIST_DIR}/qsc_ecc_keyver_bridge.c")
else()
    add_library(qsc_acvp_ecc SHARED EXCLUDE_FROM_ALL ${QSC_ACVP_ECC_FILES} "${CMAKE_CURRENT_LIST_DIR}/qsc_ecc_keyver_bridge.c")
endif()

set(QSC_ACVP_ECC_PRELIMINARY_FILES ${QSC_ACVP_ECC_FILES})
list(REMOVE_ITEM QSC_ACVP_ECC_PRELIMINARY_FILES "${QSC_ROOT}/QSC/ecdsap384.c")
add_library(qsc_acvp_ecc_preliminary SHARED ${QSC_ACVP_ECC_PRELIMINARY_FILES} "${CMAKE_CURRENT_LIST_DIR}/qsc_ecc_keyver_bridge.c")
target_include_directories(qsc_acvp_ecc PRIVATE "${QSC_ROOT}/QSC")
target_include_directories(qsc_acvp_ecc_preliminary PRIVATE "${QSC_ROOT}/QSC")
set_target_properties(qsc_acvp_ecc PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
set_target_properties(qsc_acvp_ecc_preliminary PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
if(NOT WIN32)
    target_link_libraries(qsc_acvp_ecc PRIVATE m pthread)
    target_link_options(qsc_acvp_ecc PRIVATE "LINKER:-z,defs")
    target_link_libraries(qsc_acvp_ecc_preliminary PRIVATE m pthread)
    target_link_options(qsc_acvp_ecc_preliminary PRIVATE "LINKER:-z,defs")
endif()

# Link the current parameter-specific FIPS 203/204/205 entry points separately
# from legacy CAVP wrappers. This is self-consistency smoke coverage only.
set(QSC_ACVP_PQ_SOURCES
    kyber512.c kyber768.c kyber1024.c kyberbase.c kyberbase_avx2.c
    mldsa44.c mldsa65.c mldsa87.c
    slhdsa_shake128s.c slhdsa_shake128f.c
    slhdsa_shake192s.c slhdsa_shake192f.c
    slhdsa_shake256s.c slhdsa_shake256f.c
    sha2.c sha3.c memutils.c intutils.c)
set(QSC_ACVP_PQ_FILES "")
foreach(QSC_ACVP_SOURCE IN LISTS QSC_ACVP_PQ_SOURCES)
    list(APPEND QSC_ACVP_PQ_FILES "${QSC_ROOT}/QSC/${QSC_ACVP_SOURCE}")
endforeach()
add_library(qsc_acvp_pq SHARED ${QSC_ACVP_PQ_FILES})
target_include_directories(qsc_acvp_pq PRIVATE "${QSC_ROOT}/QSC")
set_target_properties(qsc_acvp_pq PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
if(NOT WIN32)
    target_link_libraries(qsc_acvp_pq PRIVATE m pthread)
    target_link_options(qsc_acvp_pq PRIVATE "LINKER:-z,defs")
endif()

# Independent AES-GCM test bridge; no production QSC sources are modified.
add_library(qsc_acvp_aes SHARED
    "${CMAKE_CURRENT_LIST_DIR}/qsc_aes_bridge.c"
    "${QSC_ROOT}/QSC/aes.c"
    "${QSC_ROOT}/QSC/sha2.c"
    "${QSC_ROOT}/QSC/sha3.c"
    "${QSC_ROOT}/QSC/memutils.c"
    "${QSC_ROOT}/QSC/intutils.c")
target_include_directories(qsc_acvp_aes PRIVATE "${QSC_ROOT}/QSC")
set_target_properties(qsc_acvp_aes PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
if(NOT WIN32)
    target_link_libraries(qsc_acvp_aes PRIVATE m pthread)
    target_link_options(qsc_acvp_aes PRIVATE "LINKER:-z,defs")
endif()
