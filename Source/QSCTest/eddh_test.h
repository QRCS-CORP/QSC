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

#ifndef QSCTEST_EDDH_TEST_H
#define QSCTEST_EDDH_TEST_H

#include "qsctestcommon.h"

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
 * \def QSCTEST_EDDH_ITERATIONS
 * \brief The number of iterations for the ECDH stress test.
 *
 * This macro defines the number of iterations (100) to execute during the ECDH stress test.
 */
#define QSCTEST_EDDH_ITERATIONS 100

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
bool qsctest_eddh_kat_test(void);

/**
 * \brief Performs a stress test on ECDH operations.
 *
 * \details
 * This function repeatedly (QSCTEST_EDDH_ITERATIONS times) executes the following steps:
 * - Generates key pairs for two parties.
 * - Derives the shared secret from each party's perspective using the corresponding private key and the other
 *   party's public key.
 * - Verifies that the derived shared secrets are equal.
 *
 * \return Returns true if all key exchange operations are successful in every iteration.
 */
bool qsctest_eddh_operations_test(void);

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
bool qsctest_eddh_privatekey_integrity(void);

/**
 * \brief Tests the integrity of a mutated public key in ECDH.
 *
 * \details
 * This test intentionally modifies a bit in the public key and performs key exchange. The test is successful if
 * the shared secret derived using the altered public key does not match the expected result.
 *
 * \return Returns true if the altered public key fails to produce the correct shared secret.
 */
bool qsctest_eddh_publickey_integrity(void);

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
void qsctest_eddh_run(void);

#endif
