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

#ifndef QSCTEST_CHACHA_TEST_H
#define QSCTEST_CHACHA_TEST_H

#include "qsccommon.h"

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
