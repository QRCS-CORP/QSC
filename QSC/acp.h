/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_ACP_H
#define QSC_ACP_H

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
 * int main(void)
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
 *     return 0;
 * }
 * \endcode
 *
 * \section acp_links Reference Links
 * - <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 FIPS 202</a> 
 * - <a href="https://software.intel.com/content/www/us/en/develop/articles/intel-digital-random-number-generator.html">Intel RDRAND Documentation</a>
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptgenrandom">Microsoft CryptGenRandom Documentation</a>
 * - <a href="https://man7.org/linux/man-pages/man4/urandom.4.html">POSIX /dev/urandom Documentation</a>
 */

#include "common.h"

/*!
 * \def QSC_ACP_SEED_MAX
 * \brief The maximum number of bytes that can be generated in a single call to qsc_acp_generate.
 *
 * This constant limits the output size to ensure that the internal entropy aggregation and key 
 * derivation process remains within safe operational parameters.
 */
#define QSC_ACP_SEED_MAX 10240000ULL

/**
 * \brief Generate cryptographically secure random bytes.
 *
 * Aggregates entropy from multiple system sources including system statistics, hardware 
 * randomness (via RDRAND), and the system's cryptographic service provider. The collected 
 * entropy is then processed using the cSHAKE-512 algorithm to produce pseudorandom output.
 *
 * \param output:	[uint8_t*] Pointer to the output buffer that will receive the random bytes.
 * \param length:	[size_t] The number of random bytes to generate. Must not exceed QSC_ACP_SEED_MAX.
 * \return			[bool] Returns true on success, or false if an error occurred during entropy collection or random byte generation.
 *
 * \sa qsc_acp_uint16, qsc_acp_uint32, qsc_acp_uint64, qsc_cshake512_compute, qsc_rdp_generate, qsc_csp_generate
 */
QSC_EXPORT_API bool qsc_acp_generate(uint8_t* output, size_t length);

/**
 * \brief Generate a cryptographically secure random 16-bit unsigned integer.
 *
 * This function generates a 16-bit unsigned integer by calling qsc_acp_generate 
 * to obtain the necessary random bytes and assembling them in big-endian order.
 *
 * \return			[uint16_t] A 16-bit unsigned integer generated from high-quality random data.
 *
 * \sa qsc_acp_generate
 */
QSC_EXPORT_API uint16_t qsc_acp_uint16(void);

/**
 * \brief Generate a cryptographically secure random 32-bit unsigned integer.
 *
 * This function generates a 32-bit unsigned integer by calling qsc_acp_generate 
 * to obtain the necessary random bytes and assembling them in big-endian order.
 *
 * \return			[uint32_t] A 32-bit unsigned integer generated from high-quality random data.
 *
 * \sa qsc_acp_generate
 */
QSC_EXPORT_API uint32_t qsc_acp_uint32(void);

/**
 * \brief Generate a cryptographically secure random 64-bit unsigned integer.
 *
 * This function generates a 64-bit unsigned integer by calling qsc_acp_generate 
 * to obtain the necessary random bytes and assembling them in big-endian order.
 *
 * \return			[uint64_t] A 64-bit unsigned integer generated from high-quality random data.
 *
 * \sa qsc_acp_generate
 */
QSC_EXPORT_API uint64_t qsc_acp_uint64(void);

#endif
