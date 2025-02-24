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

#ifndef QSCTEST_RCS_TEST_H
#define QSCTEST_RCS_TEST_H

#include "common.h"
#include "../QSC/rcs.h"

/**
 * \file rcs_test.h
 * \brief RCS Known Answer Tests.
 *
 * \details
 * This header defines functions and macros for testing the RCS (Rijndael wide-block Cryptographic Stream cipher) implementation
 * against known answer test (KAT) vectors. New test vectors have been added for the extended modes
 * RCS-256 and RCS-512, which are sourced from the CEX cryptographic library.
 *
 * The test suite includes:
 * - KAT tests for both RCS-256 and RCS-512, verifying that the generated ciphertext (and MAC, if applicable)
 *   matches the expected outputs.
 * - Stress tests for RCS-256 and RCS-512 that use random inputs to confirm the correct operation of the cipher.
 * - A test for the extended transform API.
 * - Optionally, if the system supports AVX-512 and AES-NI and RCS is configured without authentication,
 *   wide block tests are enabled to verify that the AVX-accelerated transform produces output identical
 *   to that of sequential processing.
 *
 * \section rcs_kat_links Reference Links
 * - CEX Cryptographic Library: <a href="https://github.com/Steppenwolfe65/CEX">CEX</a>
 * - CEX RCS Tests: <a href="https://github.com/Steppenwolfe65/CEX/blob/master/Test/RCSTest.cpp">RCSTest.cpp</a>
 */

#if defined(QSC_SYSTEM_HAS_AVX512)
#	if defined(QSC_SYSTEM_AESNI_ENABLED)
#		if !defined(QSC_RCS_AUTHENTICATED)
#			define QSCTEST_RCS_WIDE_BLOCK_TESTS
#		endif
#	endif
#endif

/**
 * \def QSCTEST_RCS_TEST_CYCLES
 * \brief Number of iterations for RCS stress tests.
 *
 * This macro defines the number of test iterations (100) used in the RCS stress tests.
 */
#define QSCTEST_RCS_TEST_CYCLES 100

/**
 * \brief Tests the RCS-256 Known Answer Test (KAT) vectors from the CEX library.
 *
 * \details
 * This function verifies that the RCS-256 implementation produces the expected ciphertext and MAC
 * when encrypting a known test message using predetermined key and nonce values.
 *
 * \return Returns true if the RCS-256 KAT test passes; otherwise, false.
 */
bool qsctest_rcs256_kat(void);

/**
 * \brief Tests the RCS-512 Known Answer Test (KAT) vectors from the CEX library.
 *
 * \details
 * This function verifies that the RCS-512 implementation produces the expected ciphertext and MAC
 * for a known test message based on test vectors from the CEX cryptographic library.
 *
 * \return Returns true if the RCS-512 KAT test passes; otherwise, false.
 */
bool qsctest_rcs512_kat(void);

/**
 * \brief Stress tests the RCS-256 implementation with random inputs.
 *
 * \details
 * This function performs a stress test on the RCS-256 algorithm by encrypting and decrypting randomly
 * generated messages over a number of iterations defined by QSCTEST_RCS_TEST_CYCLES. It verifies that the
 * decrypted output matches the original input.
 *
 * \return Returns true if all RCS-256 stress test iterations pass; otherwise, false.
 */
bool qsctest_rcs256_stress_test(void);

/**
 * \brief Stress tests the RCS-512 implementation with random inputs.
 *
 * \details
 * This function repeatedly encrypts and decrypts randomly generated messages using the RCS-512 algorithm,
 * verifying that the output is consistent with the original input.
 *
 * \return Returns true if the RCS-512 stress test passes; otherwise, false.
 */
bool qsctest_rcs512_stress_test(void);

/**
 * \brief Tests the extended transform API of the RCS implementation.
 *
 * \details
 * This function validates the extended API for RCS, ensuring that the output produced by this API
 * matches the expected result.
 *
 * \return Returns true if the extended transform API test passes; otherwise, false.
 */
bool qsctest_extended_cipher_test(void);

#if defined(QSCTEST_RCS_WIDE_BLOCK_TESTS)
/**
 * \brief Tests the RCS AVX functions for equality with sequential processing.
 *
 * \details
 * When wide block tests are enabled, this function checks that the AVX-accelerated RCS transform produces
 * output identical to that of the sequential (non-AVX) implementation.
 *
 * \return Returns true if the outputs are equal; otherwise, false.
 */
bool qsctest_rcs_wide_equality(void);
#endif

/**
 * \brief Runs all RCS test functions.
 *
 * \details
 * This function executes the full suite of RCS tests, including:
 * - The Known Answer Tests (KAT) for RCS-256 and RCS-512.
 * - Stress tests for both RCS-256 and RCS-512 using random inputs.
 * - The extended transform API test.
 * - Optionally, wide block equality tests if enabled.
 *
 * Test results are printed to the console.
 */
void qsctest_rcs_run(void);


#endif
