
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSCTEST_CHACHA_TEST_H
#define QSCTEST_CHACHA_TEST_H

#include "../QSC/common.h"

/**
* \file chacha_test.h
* \brief ChaCha Known Answer Tests \n
* ChaChaP20 known answer comparison (KAT) tests. \n
* Test vectors from the official ChaCha implementation. \n
* \author John Underhill
* \date August 25, 2020
*/

#define QSCTEST_CHACHA_TEST_CYCLES 100

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	define QSCTEST_CHACHA_WIDE_BLOCK_TESTS
#endif

/**
* \brief Tests the ChaChaP20 implementation using a 128bit key.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
* RFC7539: <a href="https://tools.ietf.org/html/rfc7539">ChaCha and Poly1305 based Cipher Suites for TLS</a>
*/
bool qsctest_chacha128_kat(void);

/**
* \brief Tests the ChaChaP20 implementation using a 256bit key.
*
* \return Returns true for success
*
* \remarks <b>Test References:</b> \n
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
