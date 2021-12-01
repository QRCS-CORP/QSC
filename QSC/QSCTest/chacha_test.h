/**
* \file chacha_test.h
* \brief ChaCha Known Answer Tests \n
* ChaChaP20 known answer comparison (KAT) tests. \n
* Test vectors from the official ChaCha implementation. \n
* \author John Underhill
* \date August 25, 2020
*/

#ifndef QSCTEST_CHACHA_TEST_H
#define QSCTEST_CHACHA_TEST_H

#include "../QSC/common.h"

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
