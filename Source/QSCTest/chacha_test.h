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


#ifndef QSCTEST_CHACHA_TEST_H
#define QSCTEST_CHACHA_TEST_H

#include "../QSC/common.h"

/**
* \file chacha_test.h
* \brief ChaCha Known Answer Tests.
* \details ChaChaP20 known answer comparison (KAT) tests.
* Test vectors from the official ChaCha implementation.
*/

/**
* \file chacha_test.h
* \brief ChaCha Known Answer Tests.
* \details
* This header file contains known answer tests (KATs) for the ChaChaP20 cipher implementations.
* The tests verify the correctness of the ChaCha cipher by comparing the output of its transformation
* against expected test vectors obtained from the official ChaCha implementation.
*
* The test suite includes:
* - Known Answer Tests for ChaChaP20 using a 128bit key. Two different key setups are tested,
*   and the output is compared with precomputed expected values.
* - Known Answer Tests for ChaChaP20 using a 256bit key, similarly comparing the computed output
*   against known expected results.
* - If AVX intrinsics are enabled, wide block tests are performed for both 128bit and 256bit modes.
*   In these tests, the cipher encrypts a block of data using an AVX-accelerated implementation,
*   then decrypts it in 16-byte segments using a reference method, ensuring the final output
*   matches the original message.
*
* \section chacha_test_links Reference Links
* - RFC7539: <a href="https://tools.ietf.org/html/rfc7539">ChaCha and Poly1305 based Cipher Suites for TLS</a>
*/

/*!
* \def QSCTEST_CHACHA_TEST_CYCLES
* \brief The number of stress test repetitions
*/
#define QSCTEST_CHACHA_TEST_CYCLES 100

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
	/*!
	* \def QSCTEST_CHACHA_WIDE_BLOCK_TESTS
	* \brief Enable wide block tests
	*/
#	define QSCTEST_CHACHA_WIDE_BLOCK_TESTS
#endif

/**
* \brief Tests the ChaChaP20 implementation using a 128bit key.
*
* \return Returns true for success
*
* \remarks Test References:
* RFC7539: <a href="https://tools.ietf.org/html/rfc7539">ChaCha and Poly1305 based Cipher Suites for TLS</a>
*/
bool qsctest_chacha128_kat(void);

/**
* \brief Tests the ChaChaP20 implementation using a 256bit key.
*
* \return Returns true for success
*
* \remarks Test References:
* RFC7539: <a href="https://tools.ietf.org/html/rfc7539">ChaCha and Poly1305 based Cipher Suites for TLS</a>
*/
bool qsctest_chacha256_kat(void);


#if defined(QSCTEST_CHACHA_WIDE_BLOCK_TESTS)

/**
* \brief Tests the AVX implementations of the ChaCha-128 cipher for equivalence with the reference mode.
* Tests either the AVX, AVX2, or AVX512 modes for output equality.
*
* \return Returns true for success
*/
bool qsctest_chacha128_wide_equality(void);

/**
* \brief Tests the AVX implementations of the ChaCha-256 cipher for equivalence with the reference mode.
* Tests either the AVX, AVX2, or AVX512 modes for output equality.
*
* \return Returns true for success
*/
bool qsctest_chacha256_wide_equality(void);
#endif

/**
* \brief Run all tests.
*/
void qsctest_chacha_run(void);

#endif
