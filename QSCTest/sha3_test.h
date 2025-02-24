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

#ifndef QSCTEST_SHA3_TEST_H
#define QSCTEST_SHA3_TEST_H

#include "common.h"

/**
 * \file sha3_test.h
 * \brief SHA3, SHAKE, cSHAKE, KMAC, and KPA Known Answer Tests.
 *
 * \details
 * This header file defines the test functions for validating the implementation of the SHA3 family,
 * its extendable-output functions (SHAKE), the customizable SHAKE (cSHAKE), the Keccak-based Message Authentication Code (KMAC),
 * and the Keccak-based Parallel Authentication (KPA) functions. The test vectors used in these functions are taken
 * from official sources such as NIST FIPS 202, NIST SP800-185, and additional reference implementations (e.g., the CEX cryptographic library).
 *
 * The test suite includes:
 *
 * - **SHA3 Message Digest Tests**:  
 *   The functions \c qsctest_sha3_256_kat() and \c qsctest_sha3_512_kat() compute the 256-bit and 512-bit versions
 *   of the SHA3 hash function for various input messages. The results are compared against known answer test vectors
 *   from NIST FIPS 202 and other authoritative sources.
 *
 * - **SHAKE XOF Tests**:  
 *   The functions \c qsctest_shake_128_kat(), \c qsctest_shake_256_kat(), and \c qsctest_shake_512_kat() verify the
 *   extendable-output functions SHAKE-128, SHAKE-256, and SHAKE-512 by comparing their outputs to the expected
 *   values provided in the NIST reference package for SP800-185.
 *
 * - **cSHAKE and KMAC Tests**:  
 *   The functions \c qsctest_cshake_128_kat() and \c qsctest_cshake_256_kat() test the customizable SHAKE (cSHAKE)
 *   functions. Additionally, the functions \c qsctest_kmac_128_kat(), \c qsctest_kmac_256_kat(), and \c qsctest_kmac_512_kat()
 *   validate the KMAC implementations using keying material and customization strings.
 *
 * - **KPA Tests**:  
 *   The functions \c qsctest_kpa_256_kat() and \c qsctest_kpa_512_kat() verify the Keccak-based Parallel Authentication (KPA)
 *   functions by comparing their outputs against known answer test vectors.
 *
 * - **SIMD Equality Tests (Optional)**:  
 *   When compiling with AVX2 or AVX512 support, additional functions (such as \c qsctest_kmac128x4_equality(),
 *   \c qsctest_shake256x4_equality(), \c qsctest_kmac128x8_equality(), etc.) are provided to ensure that the
 *   SIMD-accelerated implementations produce the same output as the sequential versions.
 *
 * The function \c qsctest_sha3_run() serves as the main entry point to run all the tests in this suite,
 * printing detailed results to the console.
 * 
 * \section sha3_test_links Reference Links:
 * - <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">NIST: SHA3 FIPS-202</a>
 * - <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf">NIST: SP800-185</a>
 */


/**
 * \brief Tests the 256-bit version of the Keccak message digest.
 *
 * \details
 * Computes the SHA3-256 digest for various input messages, including the empty message, a short message,
 * a 448-bit message, and a 1600-bit message. The output is compared against known answer test vectors
 * from NIST FIPS 202 and other reliable sources.
 *
 * \return Returns true if all SHA3-256 KAT tests pass; otherwise, false.
 */
bool qsctest_sha3_256_kat(void);

/**
 * \brief Tests the 512-bit version of the Keccak message digest.
 *
 * \details
 * Computes the SHA3-512 digest for various input messages and verifies that the output matches the expected
 * known answer vectors.
 *
 * \return Returns true if the SHA3-512 KAT tests pass; otherwise, false.
 */
bool qsctest_sha3_512_kat(void);

/**
 * \brief Tests the 128-bit version of the SHAKE XOF function.
 *
 * \details
 * Computes the output of the SHAKE-128 function for given input messages (including a zero-length message
 * and a 1600-bit message) and compares the output with the expected known answer vectors from the NIST
 * SP800-185 specification.
 *
 * \return Returns true if the SHAKE-128 KAT tests pass; otherwise, false.
 */
bool qsctest_shake_128_kat(void);

/**
 * \brief Tests the 256-bit version of the SHAKE XOF function.
 *
 * \details
 * Computes the output of the SHAKE-256 function for given inputs and compares the result against expected
 * values from the NIST reference package.
 *
 * \return Returns true if the SHAKE-256 KAT tests pass; otherwise, false.
 */
bool qsctest_shake_256_kat(void);

/**
 * \brief Tests the 512-bit version of the SHAKE function.
 *
 * \details
 * Computes the output of the SHAKE-512 function for provided test messages and verifies that the output
 * matches the known answer vectors generated by the CEX cryptographic library.
 *
 * \return Returns true if the SHAKE-512 KAT tests pass; otherwise, false.
 */
bool qsctest_shake_512_kat(void);

/**
 * \brief Tests the 128-bit version of the cSHAKE function.
 *
 * \details
 * Computes the output of the cSHAKE-128 function using a specified customization string and compares
 * it with the expected known answer vectors provided by NIST and other references.
 *
 * \return Returns true if the cSHAKE-128 KAT tests pass; otherwise, false.
 */
bool qsctest_cshake_128_kat(void);

/**
 * \brief Tests the 256-bit version of the cSHAKE function.
 *
 * \details
 * Computes the cSHAKE-256 output using a provided customization string and input message, verifying the result
 * against known answer vectors.
 *
 * \return Returns true if the cSHAKE-256 KAT tests pass; otherwise, false.
 */
bool qsctest_cshake_256_kat(void);

/**
 * \brief Tests the 512-bit version of the cSHAKE function.
 *
 * \details
 * Computes the output of the cSHAKE-512 function using a given customization string and input message, and compares
 * the output to the expected KAT vectors.
 *
 * \return Returns true if the cSHAKE-512 KAT tests pass; otherwise, false.
 */
bool qsctest_cshake_512_kat(void);

/**
 * \brief Tests the 128-bit version of the KMAC function.
 *
 * \details
 * Computes the KMAC-128 output using test keys, messages, and customization strings, and verifies that the result
 * matches the known answer test vectors from the NIST SP800-185 specification.
 *
 * \return Returns true if the KMAC-128 KAT tests pass; otherwise, false.
 */
bool qsctest_kmac_128_kat(void);

/**
 * \brief Tests the 256-bit version of the KMAC function.
 *
 * \details
 * Computes the KMAC-256 output with provided input parameters and checks the result against known answer vectors.
 *
 * \return Returns true if the KMAC-256 KAT tests pass; otherwise, false.
 */
bool qsctest_kmac_256_kat(void);

/**
 * \brief Tests the 512-bit version of the KMAC function.
 *
 * \details
 * Computes the KMAC-512 output and verifies it against expected output from official test vectors.
 *
 * \return Returns true if the KMAC-512 KAT tests pass; otherwise, false.
 */
bool qsctest_kmac_512_kat(void);

/**
 * \brief Tests the 256-bit version of the Keccak-based Parallel Authentication MAC (KPA) function.
 *
 * \details
 * Computes the KPA-256 output for a fixed key and message and compares the result with the known answer vector.
 *
 * \return Returns true if the KPA-256 test passes; otherwise, false.
 */
bool qsctest_kpa_256_kat(void);

/**
 * \brief Tests the 512-bit version of the Keccak-based Parallel Authentication MAC (KPA) function.
 *
 * \details
 * Computes the KPA-512 output using fixed inputs and verifies that the result matches the expected known answer.
 *
 * \return Returns true if the KPA-512 test passes; otherwise, false.
 */
bool qsctest_kpa_512_kat(void);

#if defined(QSC_SYSTEM_HAS_AVX2)
/**
 * \brief Tests the KMAC-128 AVX2 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_kmac128x4_equality(void);

/**
 * \brief Tests the KMAC-256 AVX2 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_kmac256x4_equality(void);

/**
 * \brief Tests the KMAC-512 AVX2 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_kmac512x4_equality(void);

/**
 * \brief Tests the SHAKE-128 AVX2 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_shake128x4_equality(void);

/**
 * \brief Tests the SHAKE-256 AVX2 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_shake256x4_equality(void);

/**
 * \brief Tests the SHAKE-512 AVX2 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_shake512x4_equality(void);
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
/**
 * \brief Tests the KMAC-128 AVX512 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_kmac128x8_equality(void);

/**
 * \brief Tests the KMAC-256 AVX512 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_kmac256x8_equality(void);

/**
 * \brief Tests the KMAC-512 AVX512 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_kmac512x8_equality(void);

/**
 * \brief Tests the SHAKE-128 AVX512 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_shake128x8_equality(void);

/**
 * \brief Tests the SHAKE-256 AVX512 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_shake256x8_equality(void);

/**
 * \brief Tests the SHAKE-512 AVX512 intrinsics implementation for equality with the sequential version.
 *
 * \return Returns true if the SIMD version produces output identical to the sequential implementation; otherwise, false.
 */
bool qsctest_shake512x8_equality(void);
#endif

/**
 * \brief Runs all SHA3, SHAKE, cSHAKE, KMAC, and KPA tests.
 *
 * \details
 * This function executes the complete suite of tests for the SHA3 family and its related functions,
 * including:
 * - SHA3-256 and SHA3-512 digest tests.
 * - SHAKE (128, 256, and 512) known answer tests.
 * - cSHAKE (128, 256, and 512) known answer tests.
 * - KMAC (128, 256, and 512) known answer tests.
 * - KPA (256 and 512) known answer tests.
 *
 * Additionally, if SIMD intrinsics are available (AVX2 and/or AVX512), it runs a series of equality tests
 * to verify that the vectorized implementations produce output identical to the sequential ones.
 *
 * \remarks The test results are printed to the console.
 */
void qsctest_sha3_run(void);
#endif
