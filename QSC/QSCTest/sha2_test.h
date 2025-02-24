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

#ifndef QSCTEST_SHA2_TEST_H
#define QSCTEST_SHA2_TEST_H

#include "common.h"

/**
 * \file sha2_test.h
 * \brief SHA2, HKDF, and HMAC Known Answer Tests.
 *
 * \details
 * This header file declares a comprehensive test suite for verifying the correct operation
 * of the SHA2 family of message digests, the HKDF (HMAC-based Extract-and-Expand Key Derivation Function),
 * and the HMAC implementations. The tests use official test vectors (known answer tests or KATs)
 * drawn from NIST, RFC 5869, and RFC 4231 to ensure that:
 *
 * - **HKDF-Expand (HMAC-SHA2) Tests**:  
 *   The functions \c qsctest_hkdf_256_kat() and \c qsctest_hkdf_512_kat() compute the expanded keys using
 *   HMAC-SHA2-256 and HMAC-SHA2-512, respectively. These outputs are compared against expected values specified
 *   in RFC 5869.
 *
 * - **HMAC-SHA2 Tests**:  
 *   The functions \c qsctest_hmac_256_kat() and \c qsctest_hmac_512_kat() generate message authentication codes
 *   using SHA2-256 and SHA2-512. The resulting MAC values are compared with those provided in the official test vectors
 *   (e.g. RFC 4231).
 *
 * - **SHA2 Digest Tests**:  
 *   The functions \c qsctest_sha2_256_kat(), \c qsctest_sha2_384_kat(), and \c qsctest_sha2_512_kat() compute the
 *   256-bit, 384-bit, and 512-bit SHA2 digests for various messages. The computed hashes are verified against
 *   known answer values from the NIST SHA2 test suite.
 *
 * The overall test suite is executed by the function \c qsctest_sha2_run(), which sequentially runs each
 * test and prints the results to the console.
 * \section sha2_test_links Reference Links
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">The SHA2 Standard FIPS 180-4</a>
 * - <a href="https://www.rfc-editor.org/rfc/rfc5869">RFC 5869 -HMAC-based Extract-and-Expand Key Derivation Function (HKDF)</a>
 * - <a href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231 - Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512</a>
 */

/**
 * \brief Tests the 256-bit HKDF-Expand function using HMAC(SHA2-256).
 *
 * \details
 * This function computes expanded key material from a given key and info string using the HKDF-Expand
 * algorithm based on HMAC(SHA2-256). It compares the computed output with the expected test vector
 * as specified in RFC 5869.
 *
 * \return Returns true if the computed output matches the expected vector; otherwise, false.
 *
 * \remarks Test vectors are taken from RFC 5869.
 */
bool qsctest_hkdf_256_kat(void);

/**
 * \brief Tests the 512-bit HKDF-Expand function using HMAC(SHA2-512).
 *
 * \details
 * This function computes expanded key material using the HKDF-Expand algorithm based on HMAC(SHA2-512),
 * and then verifies that the output matches the expected test vector.
 *
 * \return Returns true if the computed output matches the expected vector; otherwise, false.
 *
 * \remarks Test vectors are taken from RFC 5869.
 */
bool qsctest_hkdf_512_kat(void);

/**
 * \brief Tests the HMAC(SHA2-256) implementation.
 *
 * \details
 * This function computes the HMAC for several test messages using SHA2-256 as the underlying hash function.
 * The computed MAC values are compared with the expected results from RFC 4231.
 *
 * \return Returns true if all computed MACs match their corresponding expected outputs; otherwise, false.
 *
 * \remarks Test vectors are taken from RFC 4231.
 */
bool qsctest_hmac_256_kat(void);

/**
 * \brief Tests the HMAC(SHA2-512) implementation.
 *
 * \details
 * This function computes the HMAC for several test messages using SHA2-512 as the underlying hash function.
 * The computed MAC values are compared with the expected results from RFC 4231.
 *
 * \return Returns true if all computed MACs match their corresponding expected outputs; otherwise, false.
 *
 * \remarks Test vectors are taken from RFC 4231.
 */
bool qsctest_hmac_512_kat(void);

/**
 * \brief Tests the SHA2-256 message digest algorithm.
 *
 * \details
 * This function computes the SHA2-256 hash for several input messages and verifies that the resulting digest
 * matches the expected known answer test vectors.
 *
 * \return Returns true if all computed SHA2-256 digests match the expected outputs; otherwise, false.
 *
 * \remarks Reference test vectors: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA256 Test Vectors</a>
 */
bool qsctest_sha2_256_kat(void);

/**
 * \brief Tests the SHA2-384 message digest algorithm.
 *
 * \details
 * This function computes the SHA2-384 hash for several input messages and verifies that the resulting digest
 * matches the expected known answer test vectors.
 *
 * \return Returns true if all computed SHA2-384 digests match the expected outputs; otherwise, false.
 *
 * \remarks Reference test vectors: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA384 Test Vectors</a>
 */
bool qsctest_sha2_384_kat(void);

/**
 * \brief Tests the SHA2-512 message digest algorithm.
 *
 * \details
 * This function computes the SHA2-512 hash for several input messages and verifies that the resulting digest
 * matches the expected known answer test vectors.
 *
 * \return Returns true if all computed SHA2-512 digests match the expected outputs; otherwise, false.
 *
 * \remarks Reference test vectors: <a href="https://www.di-mgt.com.au/sha_testvectors.html">SHA512 Test Vectors</a>
 */
bool qsctest_sha2_512_kat(void);

/**
 * \brief Runs all SHA2, HKDF, and HMAC known answer tests.
 *
 * \details
 * This function executes all of the tests defined above for the SHA2 family (SHA2-256, SHA2-384, SHA2-512),
 * HKDF (using both SHA2-256 and SHA2-512), and HMAC (using both SHA2-256 and SHA2-512). For each test,
 * it prints a success message if the output matches the known answer, or a failure message if it does not.
 */
void qsctest_sha2_run(void);

#endif
