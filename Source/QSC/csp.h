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

#ifndef QSC_CSP_H
#define QSC_CSP_H

#include "common.h"

QSC_CPLUSPLUS_ENABLED_START

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/**
 * \file csp.h
 * \brief Cryptographic System Entropy Provider Header
 *
 * \details
 * This header provides the interface for the Cryptographic System Entropy Provider.
 * It offers access to pseudo-random data generated by the system's entropy source.
 * On Windows systems, the provider uses the CryptGenRandom API; on POSIX systems,
 * it reads from the /dev/urandom device. In environments where arc4random_buf is available,
 * that function is used directly.
 *
 * Example Usage:
 * \code
 *  #include "csp.h"
 *
 *  uint8_t buffer[64];
 *  if (qsc_csp_generate(buffer, sizeof(buffer)))
 *  {
 *      // buffer now contains 64 bytes of pseudo-random data.
 *  }
 *
 *  uint32_t randomValue = qsc_csp_uint32();
 * \endcode
 *
 * This provider is recommended to be combined with additional entropy sources
 * to ensure robust randomness.
 *
 * \section csp_links Reference Links
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptgenrandom">Microsoft CryptGenRandom Documentation</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/devurandom.html">POSIX /dev/urandom Documentation</a>
 */

/*!
 * \def QSC_CSP_SEED_MAX
 * \brief The maximum number of seed bytes that can be extracted from a single generate call.
 */
#define QSC_CSP_SEED_MAX 1024000ULL

/**
 * \brief Retrieve pseudo-random bytes from the system entropy provider.
 *
 * This function fills the provided output array with pseudo-random bytes sourced from
 * the operating system's entropy mechanism. On Windows systems, it utilizes the CryptGenRandom
 * function from the Windows API, whereas on Posix systems it reads from the /dev/urandom device.
 * In environments supporting arc4random_buf, that function is used directly.
 *
 * \param output:	[uint8_t*] Pointer to the byte array where the random data will be stored.
 * \param length:	[size_t] The number of random bytes to generate. Must not exceed QSC_CSP_SEED_MAX.
 *
 * \return			[bool] Returns true if the random data was successfully generated; otherwise, false.
 *
 * \see qsc_csp_uint16(), qsc_csp_uint32(), qsc_csp_uint64()
 */
QSC_EXPORT_API bool qsc_csp_generate(uint8_t* output, size_t length);

/**
 * \brief Generate a random 16-bit unsigned integer.
 *
 * This function generates a pseudo-random 16-bit unsigned integer by retrieving the appropriate
 * number of bytes from the system entropy provider.
 *
 * \return			[uint16_t] Returns the pseudo-random 16-bit unsigned integer.
 *
 * \see qsc_csp_generate()
 */
QSC_EXPORT_API uint16_t qsc_csp_uint16(void);

/**
 * \brief Generate a random 32-bit unsigned integer.
 *
 * This function generates a pseudo-random 32-bit unsigned integer by retrieving the appropriate
 * number of bytes from the system entropy provider.
 *
 * \return			[uint32_t] Returns the pseudo-random 32-bit unsigned integer.
 *
 * \see qsc_csp_generate()
 */
QSC_EXPORT_API uint32_t qsc_csp_uint32(void);

/**
 * \brief Generate a random 64-bit unsigned integer.
 *
 * This function generates a pseudo-random 64-bit unsigned integer by retrieving the appropriate
 * number of bytes from the system entropy provider.
 *
 * \return			[uint64_t] Returns the pseudo-random 64-bit unsigned integer.
 *
 * \see qsc_csp_generate()
 */
QSC_EXPORT_API uint64_t qsc_csp_uint64(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
