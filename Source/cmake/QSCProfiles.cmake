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

# Application profiles select independently-linkable algorithm translation units.
# Existing TLS/X.509 dispatch is not modified or algorithm-pruned.
set(QSC_SUPPORTED_PROFILES
    FULL BOOT_VERIFY DEVICE_IDENTITY CRYPTO_CLASSICAL CRYPTO_PQC3 CRYPTO_PQC5
    CRYPTO_HYBRID CLOUD_HSM EDGE_GATEWAY TLS_CLIENT TLS_SERVER INDUSTRIAL_OT
    ROBOT_EDGE AI_MODEL_TRUST VEHICLE_ECU CUSTOM
)

function(qsc_resolve_custom _selection _out_files _out_algorithms)
    string(REPLACE "," ";" _requested "${_selection}")
    if(NOT _requested)
        message(FATAL_ERROR "QSC_PROFILE=CUSTOM requires QSC_CUSTOM_ALGORITHMS")
    endif()
    set(_files ${QSC_COMPACT_BASE_SOURCES})
    set(_algs "")
    foreach(_algorithm IN LISTS _requested)
        string(TOUPPER "${_algorithm}" _algorithm)
        string(STRIP "${_algorithm}" _algorithm)
        if(_algorithm STREQUAL "SHA2")
            list(APPEND _files sha2.c)
        elseif(_algorithm STREQUAL "SHA3")
            list(APPEND _files sha3.c)
        elseif(_algorithm STREQUAL "AES_GCM")
            list(APPEND _files aes.c sha2.c sha3.c)
        elseif(_algorithm STREQUAL "X25519")
            list(APPEND _files eddh25519.c ed25519.c sha2.c sha3.c csp.c)
        elseif(_algorithm STREQUAL "ECDSA_P256")
            list(APPEND _files ecdsap256.c sha2.c sha3.c csp.c)
        elseif(_algorithm STREQUAL "ECDSA_P384")
            list(APPEND _files ecdsap384.c sha2.c sha3.c csp.c)
        elseif(_algorithm STREQUAL "MLKEM768")
            list(APPEND _files kyber768.c sha3.c)
        elseif(_algorithm STREQUAL "MLKEM1024")
            list(APPEND _files kyber1024.c sha3.c)
        elseif(_algorithm STREQUAL "MLDSA65")
            list(APPEND _files mldsa65.c sha3.c)
        elseif(_algorithm STREQUAL "MLDSA87")
            list(APPEND _files mldsa87.c sha3.c)
        elseif(_algorithm STREQUAL "SLHDSA_SHAKE128S")
            list(APPEND _files slhdsa_shake128s.c sha2.c sha3.c)
        elseif(_algorithm STREQUAL "SLHDSA_SHAKE256S")
            list(APPEND _files slhdsa_shake256s.c sha2.c sha3.c)
        else()
            message(FATAL_ERROR "Unsupported QSC_CUSTOM_ALGORITHMS entry: ${_algorithm}")
        endif()
        list(APPEND _algs "${_algorithm}")
    endforeach()
    list(REMOVE_DUPLICATES _files)
    list(REMOVE_DUPLICATES _algs)
    set(${_out_files} "${_files}" PARENT_SCOPE)
    set(${_out_algorithms} "${_algs}" PARENT_SCOPE)
endfunction()

function(qsc_resolve_profile _profile _out_files _out_algorithms)
    if(NOT _profile IN_LIST QSC_SUPPORTED_PROFILES)
        message(FATAL_ERROR "Unsupported QSC_PROFILE '${_profile}'")
    endif()
    if(_profile STREQUAL "FULL")
        set(_files ${QSC_ALL_SOURCES})
        set(_algs ALL)
    elseif(_profile STREQUAL "CUSTOM")
        qsc_resolve_custom("${QSC_CUSTOM_ALGORITHMS}" _files _algs)
    elseif(_profile MATCHES "^(EDGE_GATEWAY|TLS_CLIENT|TLS_SERVER)$")
        set(_files ${QSC_TLS_COMPATIBLE_SOURCES})
        set(_algs "TLS13;X509;SHA2;SHA3;TLS_EXISTING_DISPATCH")
    elseif(_profile STREQUAL "CLOUD_HSM")
        set(_files ${QSC_COMPACT_BASE_SOURCES} sha2.c sha3.c aes.c csp.c
            ecdsap256.c ecdsap384.c ed25519.c eddh25519.c
            kyber768.c kyber1024.c mldsa65.c mldsa87.c)
        set(_algs "ECDSA_P256;ECDSA_P384;X25519;MLKEM768;MLKEM1024;MLDSA65;MLDSA87;SHA2;SHA3;AES_GCM")
    elseif(_profile MATCHES "^(BOOT_VERIFY|AI_MODEL_TRUST)$")
        set(_files ${QSC_COMPACT_BASE_SOURCES} sha2.c sha3.c csp.c ecdsap256.c mldsa65.c)
        set(_algs "ECDSA_P256_VERIFY;MLDSA65_VERIFY;SHA2;SHA3")
    elseif(_profile MATCHES "^(DEVICE_IDENTITY|CRYPTO_HYBRID|INDUSTRIAL_OT|ROBOT_EDGE)$")
        set(_files ${QSC_COMPACT_BASE_SOURCES} sha2.c sha3.c aes.c csp.c ed25519.c ${QSC_CLASSICAL_SOURCES} ${QSC_PQC3_SOURCES})
        set(_algs "X25519;ECDSA_P256;MLKEM768;MLDSA65;SHA2;SHA3;AES_GCM")
    elseif(_profile STREQUAL "VEHICLE_ECU")
        set(_files ${QSC_COMPACT_BASE_SOURCES} sha2.c sha3.c aes.c csp.c ed25519.c eddh25519.c ecdsap256.c ecdsap384.c kyber768.c mldsa65.c)
        set(_algs "X25519;ECDSA_P256;ECDSA_P384;MLKEM768;MLDSA65;SHA2;SHA3;AES_GCM")
    elseif(_profile STREQUAL "CRYPTO_CLASSICAL")
        set(_files ${QSC_COMPACT_BASE_SOURCES} sha2.c sha3.c aes.c csp.c ed25519.c ${QSC_CLASSICAL_SOURCES})
        set(_algs "X25519;ECDSA_P256;SHA2;AES_GCM")
    elseif(_profile STREQUAL "CRYPTO_PQC3")
        set(_files ${QSC_COMPACT_BASE_SOURCES} sha3.c aes.c ${QSC_PQC3_SOURCES})
        set(_algs "MLKEM768;MLDSA65;SHA3;AES_GCM")
    elseif(_profile STREQUAL "CRYPTO_PQC5")
        set(_files ${QSC_COMPACT_BASE_SOURCES} sha3.c aes.c ${QSC_PQC5_SOURCES})
        set(_algs "MLKEM1024;MLDSA87;SHA3;AES_GCM")
    endif()
    list(REMOVE_DUPLICATES _files)
    set(${_out_files} "${_files}" PARENT_SCOPE)
    set(${_out_algorithms} "${_algs}" PARENT_SCOPE)
endfunction()
