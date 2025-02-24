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

#ifndef QSCTEST_ECDH_TEST_H
#define QSCTEST_ECDH_TEST_H

#include "common.h"

/**
 * \file ecdh_test.h
 * \brief ECDH Test Functions.
 *
 * \details
 * This header defines functions to test the ECDH (Elliptic Curve Diffie-Hellman) implementation.
 * The test suite includes:
 *
 * - A Known Answer Test (KAT) that verifies the generated public and private keys, as well as the derived
 *   shared secret against expected test vectors.
 *
 * - A stress test that repeatedly generates key pairs, performs key exchange, and verifies that both parties
 *   derive an identical shared secret over a number of iterations.
 *
 * - Integrity tests that check whether altering a secret key or a public key causes the derived shared secret
 *   to differ from the expected result.
 *
 * \section ecdh_test_links Reference Links
 * - ECDH Overview: <a href="https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman">Elliptic Curve Diffie-Hellman</a>
 */

/**
 * \def QSCTEST_ECDH_ITERATIONS
 * \brief The number of iterations for the ECDH stress test.
 *
 * This macro defines the number of iterations (100) to execute during the ECDH stress test.
 */
#define QSCTEST_ECDH_ITERATIONS 100

/**
 * \brief Performs the ECDH Known Answer Test (KAT).
 *
 * \details
 * This test verifies that:
 * - The generated public and private keys match the expected test vectors.
 * - The shared secret derived by both parties (Alice and Bob) is identical.
 * - The derived shared secret matches the known answer provided in the test vector.
 *
 * \return Returns true if the generated keys and shared secret match the expected values.
 */
bool qsctest_ecdh_kat_test(void);

/**
 * \brief Performs a stress test on ECDH operations.
 *
 * \details
 * This function repeatedly (QSCTEST_ECDH_ITERATIONS times) executes the following steps:
 * - Generates key pairs for two parties.
 * - Derives the shared secret from each party's perspective using the corresponding private key and the other
 *   party's public key.
 * - Verifies that the derived shared secrets are equal.
 *
 * \return Returns true if all key exchange operations are successful in every iteration.
 */
bool qsctest_ecdh_operations_test(void);

/**
 * \brief Tests the integrity of a mutated secret key in ECDH.
 *
 * \details
 * This test deliberately flips a bit in the secret key and then performs a key exchange. The test passes if
 * the derived shared secret differs from the expected result, indicating that the alteration in the secret key
 * is detected.
 *
 * \return Returns true if the altered secret key fails to produce the correct shared secret.
 */
bool qsctest_ecdh_privatekey_integrity(void);

/**
 * \brief Tests the integrity of a mutated public key in ECDH.
 *
 * \details
 * This test intentionally modifies a bit in the public key and performs key exchange. The test is successful if
 * the shared secret derived using the altered public key does not match the expected result.
 *
 * \return Returns true if the altered public key fails to produce the correct shared secret.
 */
bool qsctest_ecdh_publickey_integrity(void);

/**
 * \brief Runs all ECDH test functions.
 *
 * \details
 * This function executes the complete set of ECDH tests, including:
 * - The Known Answer Test (KAT) for verifying key generation and shared secret derivation.
 * - A stress test for repeated key exchange operations.
 * - Integrity tests for both secret key and public key alterations.
 *
 * The outcome of each test is printed to the console.
 */
void qsctest_ecdh_run(void);

#endif
