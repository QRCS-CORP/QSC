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

# Optional HSM provider modules; external SDK dependencies are opt-in.
set(QSC_SUPPORTED_HARDWARE_PROVIDERS PKCS11 NCRYPT TPM ATECC SE050 PSA PSA_NATIVE PLATFORM)
function(qsc_resolve_hardware _out_sources _out_defs _out_libs)
    set(_src "")
    set(_defs "")
    set(_libs "")
    if(NOT QSC_ENABLE_HARDWARE)
        if(QSC_HARDWARE_PROVIDERS)
            message(FATAL_ERROR "QSC_HARDWARE_PROVIDERS requires QSC_ENABLE_HARDWARE=ON")
        endif()
    else()
        list(APPEND _src hwprovider.c)
        list(APPEND _defs QSC_HARDWARE_ENABLED)
        string(REPLACE "," ";" _providers "${QSC_HARDWARE_PROVIDERS}")
        string(TOUPPER "${_providers}" _providers)
        list(REMOVE_DUPLICATES _providers)
        foreach(_provider IN LISTS _providers)
            if(NOT _provider IN_LIST QSC_SUPPORTED_HARDWARE_PROVIDERS)
                message(FATAL_ERROR "Unknown QSC hardware provider ${_provider}")
            endif()
            if(_provider STREQUAL "PKCS11" OR _provider STREQUAL "SE050")
                list(APPEND _src async.c sysutils.c cpuidex.c consoleutils.c stringutils.c
                    p11loader.c p11session.c p11keys.c p11sign.c p11agree.c)
                list(APPEND _defs QSC_HARDWARE_PKCS11_ENABLED)
                if(_provider STREQUAL "SE050")
                    list(APPEND _src hwse050.c)
                    list(APPEND _defs QSC_HARDWARE_SE050_ENABLED)
                endif()
            elseif(_provider STREQUAL "NCRYPT")
                if(NOT WIN32)
                    message(FATAL_ERROR "NCRYPT is Windows-only")
                endif()
                list(APPEND _src hwncrypt.c)
                list(APPEND _defs QSC_HARDWARE_NCRYPT_ENABLED)
                list(APPEND _libs ncrypt bcrypt)
            elseif(_provider STREQUAL "TPM")
                if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
                    message(FATAL_ERROR "Native TPM2-TSS integration requires Linux")
                endif()
                find_package(PkgConfig REQUIRED)
                pkg_check_modules(QSC_TSS REQUIRED IMPORTED_TARGET tss2-esys tss2-tctildr)
                list(APPEND _src hwtpm.c hwtpmquote.c ecdhp256.c)
                list(APPEND _defs QSC_HARDWARE_TPM_ENABLED)
                list(APPEND _libs PkgConfig::QSC_TSS)
            elseif(_provider STREQUAL "ATECC")
                list(APPEND _src hwatecc.c)
                list(APPEND _defs QSC_HARDWARE_ATECC_ENABLED)
            elseif(_provider STREQUAL "PSA" OR _provider STREQUAL "PSA_NATIVE")
                list(APPEND _src hwpsa.c)
                list(APPEND _defs QSC_HARDWARE_PSA_ENABLED)
                if(_provider STREQUAL "PSA_NATIVE")
                    if(NOT EXISTS "${QSC_PSA_INCLUDE_DIR}/psa/crypto.h" OR NOT EXISTS "${QSC_PSA_LIBRARY}")
                        message(FATAL_ERROR "PSA_NATIVE requires QSC_PSA_INCLUDE_DIR and QSC_PSA_LIBRARY")
                    endif()
                    list(APPEND _src hwpsanative.c)
                    list(APPEND _defs QSC_HARDWARE_PSA_NATIVE_ENABLED)
                    list(APPEND _libs "${QSC_PSA_LIBRARY}")
                endif()
            elseif(_provider STREQUAL "PLATFORM")
                list(APPEND _src hwplatform.c)
                list(APPEND _defs QSC_HARDWARE_PLATFORM_ENABLED)
            endif()
        endforeach()
        if(QSC_PROFILE MATCHES "^(FULL|EDGE_GATEWAY|TLS_CLIENT|TLS_SERVER)$")
            if("PKCS11" IN_LIST _providers OR "SE050" IN_LIST _providers)
                list(APPEND _src hwpkcs11tls.c)
            endif()
            if("NCRYPT" IN_LIST _providers)
                list(APPEND _src hwncrypttls.c)
            endif()
        endif()
    endif()
    list(REMOVE_DUPLICATES _src)
    list(REMOVE_DUPLICATES _defs)
    list(REMOVE_DUPLICATES _libs)
    set(${_out_sources} "${_src}" PARENT_SCOPE)
    set(${_out_defs} "${_defs}" PARENT_SCOPE)
    set(${_out_libs} "${_libs}" PARENT_SCOPE)
endfunction()
