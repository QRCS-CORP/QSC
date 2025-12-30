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

#ifndef QSC_CPUIDEX_H
#define QSC_CPUIDEX_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

#if defined (QSC_HAS_CPUID)

/*!
 * \file cpuidex.h
 * \brief Retrieves CPU features and capabilities.
 *
 * \details
 * This header provides functions and type definitions for detecting and retrieving the CPU's
 * supported features and capabilities. It leverages the CPUID instruction and additional methods
 * to identify the availability of hardware-accelerated cryptographic instructions (e.g., AES-NI, AVX, AVX2,
 * AVX512, and ARM NEON), along with other processor attributes such as cache sizes, core counts,
 * and clock frequencies. The header also defines constants for the CPU serial number and vendor string lengths,
 * and enumerates supported CPU manufacturer types.
 *
 * \par Example Usage:
 * \code
 * qsc_cpuidex_cpu_features features;
 * if (qsc_cpuidex_features_set(&features))
 * {
 *     qsc_cpuidex_print_stats();
 * }
 * \endcode
 *
 * \section cpuidex_links Reference Links:
 * - <a href="https://software.intel.com/sites/default/files/managed/2b/50/325462-002.pdf">Developer's Manual, Volume 2A: Instruction Set Reference</a>
 * - <a href="https://developer.amd.com/resources/developer-guides-manuals/">AMD64 Architecture Programmer's Manual, Volume 2</a>
 *
 * \section keywords_sec Keywords:
 * CPUID, CPU detection, AES-NI, AVX, AVX2, AVX512, NEON, cryptographic instructions, CPU features, hardware acceleration
 */

/*!
 * \def QSC_CPUIDEX_SERIAL_SIZE
 * \brief The CPU serial number length (in bytes).
 */
#define QSC_CPUIDEX_SERIAL_SIZE 12ULL

#if defined(QSC_SYSTEM_OS_MAC) && defined(QSC_SYSTEM_COMPILER_GCC)
	/*!
	 * \def QSC_CPUIDEX_VENDOR_SIZE
	 * \brief The CPU vendor name length for Apple systems using GCC.
	 */
	#define QSC_CPUIDEX_VENDOR_SIZE 32
#else
	/*!
	 * \def QSC_CPUIDEX_VENDOR_SIZE
	 * \brief The CPU vendor name length.
	 */
	#define QSC_CPUIDEX_VENDOR_SIZE 12ULL
#endif

/*!
 * \enum qsc_cpuidex_cpu_type
 * \brief The detectable CPU architectures.
 */
typedef enum
{
    qsc_cpuid_unknown = 0x00U,  /*!< The CPU type is unknown. */
    qsc_cpuid_amd     = 0x01U,  /*!< The CPU type is AMD. */
    qsc_cpuid_intel   = 0x02U,  /*!< The CPU type is Intel. */
    qsc_cpuid_via     = 0x03U,  /*!< The CPU type is VIA. */
    qsc_cpuid_hygion  = 0x04U   /*!< The CPU type is Hygion. */
} qsc_cpuidex_cpu_type;

/*!
 * \struct qsc_cpuidex_cpu_features
 * \brief Contains the CPU feature availability.
 *
 * This structure holds flags and parameters indicating the availability of various
 * CPU features such as AES-NI, AVX, NEON, and others. It also stores details about cache sizes,
 * frequency, and manufacturer-specific information.
 */
QSC_EXPORT_API typedef struct
{
    bool adx;               /*!< [bool]  True if ADX instructions are available. */
    bool aesni;             /*!< [bool]  True if AES-NI instructions are available. */
    bool pcmul;             /*!< [bool]  True if PCLMULQDQ (carry-less multiplication) is available. */
    bool armv7;             /*!< [bool]  True if ARMv7 features are detected. */
    bool neon;              /*!< [bool]  True if NEON SIMD instructions are available. */
    bool sha256;            /*!< [bool]  True if SHA-256 instructions are available. */
    bool sha512;            /*!< [bool]  True if SHA-512 instructions are available. */
    bool sha3;              /*!< [bool]  True if SHA3 instructions are available. */
    bool avx;               /*!< [bool]  True if AVX instructions are available. */
    bool avx2;              /*!< [bool]  True if AVX2 instructions are available. */
    bool avx512f;           /*!< [bool]  True if AVX512 Foundation instructions are available. */
    bool hyperthread;       /*!< [bool]  True if hyper-threading is enabled. */
    bool rdrand;            /*!< [bool]  True if the RDRAND instruction is supported. */
    bool rdtcsp;            /*!< [bool]  True if the RDTCSP instruction is supported. */
    uint32_t cacheline;     /*!< [uint32_t] The CPU cache line size (in bytes). */
    uint32_t cores;         /*!< [uint32_t] The number of physical cores. */
    uint32_t cpus;          /*!< [uint32_t] The number of logical processors (CPUs). */
    uint32_t freqbase;      /*!< [uint32_t] The base CPU frequency (in Hz). */
    uint32_t freqmax;       /*!< [uint32_t] The maximum CPU frequency (in Hz). */
    uint32_t freqref;       /*!< [uint32_t] The reference CPU frequency (in Hz). */
    uint32_t l1cache;       /*!< [uint32_t] The size of the L1 cache (in bytes). */
    uint32_t l1cacheline;   /*!< [uint32_t] The L1 cache line size (in bytes). */
    uint32_t l2associative; /*!< [uint32_t] The associativity of the L2 cache. */
    uint32_t l2cache;       /*!< [uint32_t] The size of the L2 cache (in bytes). */
    char serial[QSC_CPUIDEX_SERIAL_SIZE];  /*!< [char[]] CPU serial number. */
    char vendor[QSC_CPUIDEX_VENDOR_SIZE];  /*!< [char[]] CPU vendor name. */
    qsc_cpuidex_cpu_type cputype;          /*!< [qsc_cpuidex_cpu_type] CPU manufacturer type. */
} qsc_cpuidex_cpu_features;

/**
 * \brief Populate the CPU features structure with detected CPU capabilities.
 *
 * \param features: [qsc_cpuidex_cpu_features* const] Pointer to a qsc_cpuidex_cpu_features structure to populate.
 *
 * \return      [bool] Returns true if the features were successfully detected; false otherwise.
 */
QSC_EXPORT_API bool qsc_cpuidex_features_set(qsc_cpuidex_cpu_features* const features);

/**
 * \brief Print the detected CPU features to the console.
 *
 * This function outputs the CPU capabilities (for example, AVX, AESNI, cache size, vendor)
 * to the console.
 */
QSC_EXPORT_API void qsc_cpuidex_print_stats(void);

#else

/* avoid warning C4206 : translation unit is empty */
typedef int dummy_cpuidex_translation_unit;

#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
