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

#ifndef QSCTEST_ECDSA_TEST_H
#define QSCTEST_ECDSA_TEST_H

#include "qsctestcommon.h"

/**
 * \file ecdsa_test.h
 * \brief ECDSA P-256 test functions.
 *
 * \details
 * This header defines functions for testing the ECDSA P-256 implementation.
 * The test suite includes the following:
 *
 * - A known answer style test that validates deterministic seeded key generation,
 *   message signing, and signature verification using fixed messages of various
 *   lengths. This test ensures that the implementation produces stable outputs
 *   for a fixed seed and that signatures verify successfully against the
 *   corresponding public key.
 *
 * - A private key integrity test that deliberately mutates the secret key and
 *   verifies that the resulting signature fails verification, confirming that
 *   any alteration in the secret key is detected.
 *
 * - A public key integrity test that modifies a bit in the public key to ensure
 *   that signature verification fails when the public key has been tampered with.
 *
 * - A signature integrity test that flips bits in the generated signature to
 *   verify that even minor modifications cause the verification to fail.
 *
 * - A stress test that repeatedly signs and verifies a message over many
 *   iterations and performs additional wellness checks, including internal
 *   self-test verification, key-pair regeneration checks, and recovered-message
 *   validation.
 *
 * These tests collectively ensure both the correctness and resilience of the
 * ECDSA P-256 implementation.
 */

/**
 * \def QSCTEST_ECDSA_ITERATIONS
 * \brief Number of iterations to perform in the ECDSA stress test.
 *
 * When compiled in debug mode (_DEBUG defined), the number of iterations is set to 10.
 * Otherwise, it is set to 100.
 */
#ifdef _DEBUG
#   define QSCTEST_ECDSA_ITERATIONS 1
#else
#   define QSCTEST_ECDSA_ITERATIONS 10
#endif

/**
 * \def QSCTEST_ECDSA_MSG0_SIZE
 * \brief Size in bytes of the first test message used in ECDSA tests.
 */
#define QSCTEST_ECDSA_MSG0_SIZE 32

/**
 * \def QSCTEST_ECDSA_MSG1_SIZE
 * \brief Size in bytes of the second test message used in ECDSA tests.
 */
#define QSCTEST_ECDSA_MSG1_SIZE 64

/**
 * \def QSCTEST_ECDSA_MSG2_SIZE
 * \brief Size in bytes of the third test message used in ECDSA tests.
 */
#define QSCTEST_ECDSA_MSG2_SIZE 96

/**
 * \def QSCTEST_ECDSA_MSG3_SIZE
 * \brief Size in bytes of the fourth test message used in ECDSA tests.
 */
#define QSCTEST_ECDSA_MSG3_SIZE 128

/**
 * \brief Test the ECDSA known answer vectors.
 *
 * This function tests seeded key generation, message signing, and signature
 * verification against fixed inputs for messages of varying lengths. It ensures
 * that the generated public and private keys are stable for a given seed and
 * that the produced signatures verify successfully.
 *
 * \return Returns true if all known answer tests pass.
 */
bool qsctest_ecdsa_kat_test(void);

/**
 * \brief Test the validity of a mutated secret key.
 *
 * This function deliberately alters a portion of the private key and attempts to
 * sign a message. The test passes only if the resulting signature verification
 * fails, indicating that any modification to the secret key is correctly
 * detected.
 *
 * \return Returns true if the test is successful.
 */
bool qsctest_ecdsa_privatekey_integrity(void);

/**
 * \brief Test the validity of a mutated public key.
 *
 * This function mutates the public key and verifies that signature verification
 * fails when using the altered public key.
 *
 * \return Returns true if the test is successful.
 */
bool qsctest_ecdsa_publickey_integrity(void);

/**
 * \brief Test the validity of a mutated signature.
 *
 * This function tests signature sensitivity by flipping bits in the signature.
 * It verifies that even minor alterations cause the signature verification to fail.
 *
 * \return Returns true if the test is successful.
 */
bool qsctest_ecdsa_signature_integrity(void);

/**
 * \brief Stress test the key generation, signing, and verification operations.
 *
 * This function performs a series of iterations where a message is signed and the
 * resulting signature is verified. It also performs wellness checks during each
 * iteration, including internal self-test validation, signature-length checks,
 * and recovered-message verification.
 *
 * \return Returns true if all stress and wellness tests pass.
 */
bool qsctest_ecdsa_stress_test(void);

/**
 * \brief Run the ECDSA implementation stress and correctness tests.
 *
 * This function executes the known answer tests, the integrity tests for keys
 * and signatures, and the stress test, printing the result of each test to the console.
 */
void qsctest_ecdsa_run(void);

#endif
