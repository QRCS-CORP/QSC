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

#ifndef QSC_ACP_H
#define QSC_ACP_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*! 
 * \file acp.h
 * \brief An implementation of the Auto Entropy Collection Provider (ACP).
 *
 * \details
 * The Auto Entropy Collection Provider (ACP) is a comprehensive entropy gathering 
 * module designed to supply cryptographically secure random data. It aggregates 
 * entropy from multiple sources including system timers, system statistics, and 
 * hardware-based randomness via the RDRAND instruction. In addition, it leverages 
 * platform-specific providers such as Microsoft CryptGenRandom on Windows and 
 * /dev/urandom on POSIX systems when hardware-based sources are unavailable or 
 * insufficient. The collected entropy is processed using the cSHAKE-512 algorithm 
 * to derive a primary key that is then used to generate pseudorandom output.
 *
 * \section features Features
 * - Aggregates entropy from system-level statistics and timers.
 * - Integrates hardware-based randomness through the RDRAND instruction, with a fallback 
 *   to system cryptographic service providers (e.g., CryptGenRandom, /dev/urandom).
 * - Uses the cSHAKE-512 algorithm for robust key derivation and pseudorandom number generation.
 *
 * \section details Implementation Details
 * The ACP implementation employs a layered approach to entropy collection:
 * - \b System Statistics: Uses system timestamps, computer names, process IDs, user names, and uptime.
 * - \b Drive and Memory Statistics: Retrieves drive space and memory usage information.
 * - \b Hardware Randomness: Utilizes the RDRAND instruction for high-quality randomness; if unavailable or failing,
 *   it falls back to the system cryptographic service provider (e.g., CryptGenRandom on Windows, /dev/urandom on POSIX systems).
 * - \b Key Derivation: Aggregated entropy is processed via the cSHAKE-512 function (see qsc_cshake512_compute)
 *   to produce the final pseudorandom output.
 * 
 * \section usage Usage Example
 * \code
 * #include "acp.h"
 *
 * int32_t main(void)
 * {
 *     uint8_t random_bytes[64];
 *     if (qsc_acp_generate(random_bytes, sizeof(random_bytes)))
 *     {
 *         // random_bytes now contains 64 bytes of cryptographically secure random data.
 *     }
 *
 *     uint16_t rand16 = qsc_acp_uint16();
 *     uint32_t rand32 = qsc_acp_uint32();
 *     uint64_t rand64 = qsc_acp_uint64();
 *
 *     return 0U;
 * }
 * \endcode
 *
 * \section acp_links Reference Links
 * - <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 FIPS 202</a> 
 * - <a href="https://software.intel.com/content/www/us/en/develop/articles/intel-digital-random-number-generator.html">Intel RDRAND Documentation</a>
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptgenrandom">Microsoft CryptGenRandom Documentation</a>
 * - <a href="https://man7.org/linux/man-pages/man4/urandom.4.html">POSIX /dev/urandom Documentation</a>
 */

/*!
 * \def QSC_ACP_SEED_MAX
 * \brief The maximum number of bytes that can be generated in a single call to qsc_acp_generate.
 *
 * \details This constant limits the output size to ensure that the internal entropy aggregation and key
 * derivation process remains within safe operational parameters.
 */
#define QSC_ACP_SEED_MAX 10240000U

/**
 * \brief Generate cryptographically secure random bytes.
 *
 * \details Aggregates entropy from multiple system sources including system statistics, hardware
 * randomness (via RDRAND), and the system's cryptographic service provider. The collected 
 * entropy is then processed using the cSHAKE-512 algorithm to produce pseudorandom output.
 *
 * \param output: [uint8_t*] Pointer to the output buffer that will receive the random bytes.
 * \param length: [size_t] The number of random bytes to generate. Must not exceed QSC_ACP_SEED_MAX.
 * \return [bool] Returns true on success, or false if an error occurred during entropy collection or random byte generation.
 *
 * \sa qsc_acp_uint16, qsc_acp_uint32, qsc_acp_uint64, qsc_cshake512_compute, qsc_rdp_generate, qsc_csp_generate
 */
QSC_EXPORT_API bool qsc_acp_generate(uint8_t* output, size_t length);

/**
 * \brief Generate a cryptographically secure random 16-bit unsigned integer.
 *
 * \details This function generates a 16-bit unsigned integer by calling qsc_acp_generate
 * to obtain the necessary random bytes and assembling them in big-endian order.
 *
 * \return [uint16_t] A 16-bit unsigned integer generated from high-quality random data.
 *
 * \sa qsc_acp_generate
 */
QSC_EXPORT_API uint16_t qsc_acp_uint16(void);

/**
 * \brief Generate a cryptographically secure random 32-bit unsigned integer.
 *
 * \details This function generates a 32-bit unsigned integer by calling qsc_acp_generate
 * to obtain the necessary random bytes and assembling them in big-endian order.
 *
 * \return [uint32_t] A 32-bit unsigned integer generated from high-quality random data.
 *
 * \sa qsc_acp_generate
 */
QSC_EXPORT_API uint32_t qsc_acp_uint32(void);

/**
 * \brief Generate a cryptographically secure random 64-bit unsigned integer.
 *
 * \details This function generates a 64-bit unsigned integer by calling qsc_acp_generate
 * to obtain the necessary random bytes and assembling them in big-endian order.
 *
 * \return [uint64_t] A 64-bit unsigned integer generated from high-quality random data.
 *
 * \sa qsc_acp_generate
 */
QSC_EXPORT_API uint64_t qsc_acp_uint64(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
