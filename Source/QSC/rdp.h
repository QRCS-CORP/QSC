/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef QSC_RDP_H
#define QSC_RDP_H

#include "common.h"

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
#define QSC_RDP_SEED_MAX 1024000ULL

/**
 * \brief Generate an array of random bytes using the RDRAND entropy provider.
 *
 * \param output:	[uint8_t*] Pointer to the output byte array.
 * \param length:	[size_t] The number of bytes to generate.
 *
 * \return			[bool] Returns true if the entropy generation was successful, false otherwise.
 */
QSC_EXPORT_API bool qsc_rdp_generate(uint8_t* output, size_t length);

/**
 * \brief Generate a random 16-bit unsigned integer using the RDRAND entropy provider.
 *
 * \return			[uint16_t] Returns a random 16-bit unsigned integer.
 */
QSC_EXPORT_API uint16_t qsc_rdp_uint16(void);

/**
 * \brief Generate a random 32-bit unsigned integer using the RDRAND entropy provider.
 *
 * \return			[uint32_t] Returns a random 32-bit unsigned integer.
 */
QSC_EXPORT_API uint32_t qsc_rdp_uint32(void);

/**
 * \brief Generate a random 64-bit unsigned integer using the RDRAND entropy provider.
 *
 * \return			[uint64_t] Returns a random 64-bit unsigned integer.
 */
QSC_EXPORT_API uint64_t qsc_rdp_uint64(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
