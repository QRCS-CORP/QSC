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

#ifndef QSC_RDP_H
#define QSC_RDP_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file rdp.h
 * \brief RDRAND Entropy Provider (RDP).
 *
 * \details
 * This module provides access to the Intel RDRAND entropy provider, which extracts 
 * hardware-generated random numbers from a CPU with RDRAND support. While RDP is 
 * suitable as an entropy source, it is recommended to be combined with other entropy 
 * providers to seed a MAC or DRBG function for higher quality random output.
 *
 * The ACP entropy provider is the recommended alternative in this library for 
 * ensuring strong cryptographic randomness.
 *
 * \code
 * // Example usage:
 * uint8_t entropy[64];
 * if (qsc_rdp_generate(entropy, sizeof(entropy))) {
 *     // Use the entropy for seeding a DRBG or MAC function
 * }
 * \endcode
 *
 * \section rdp_links Reference Links:
 * - <a href="https://software.intel.com/en-us/articles/intel-digital-random-number-generator">Intel RDRAND Documentation</a>
 */

/*!
 * \def QSC_RDP_SEED_MAX
 * \brief The maximum seed size that can be extracted from a single generate call.
 */
#define QSC_RDP_SEED_MAX 1024000U

/**
 * \brief Generate an array of random bytes using the RDRAND entropy provider.
 *
 * \param output: [uint8_t*] Pointer to the output byte array.
 * \param length: [size_t] The number of bytes to generate.
 *
 * \return [bool] Returns true if the entropy generation was successful, false otherwise.
 */
QSC_EXPORT_API bool qsc_rdp_generate(uint8_t* output, size_t length);

/**
 * \brief Generate a random 16-bit unsigned integer using the RDRAND entropy provider.
 *
 * \return [uint16_t] Returns a random 16-bit unsigned integer.
 */
QSC_EXPORT_API uint16_t qsc_rdp_uint16(void);

/**
 * \brief Generate a random 32-bit unsigned integer using the RDRAND entropy provider.
 *
 * \return [uint32_t] Returns a random 32-bit unsigned integer.
 */
QSC_EXPORT_API uint32_t qsc_rdp_uint32(void);

/**
 * \brief Generate a random 64-bit unsigned integer using the RDRAND entropy provider.
 *
 * \return [uint64_t] Returns a random 64-bit unsigned integer.
 */
QSC_EXPORT_API uint64_t qsc_rdp_uint64(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
