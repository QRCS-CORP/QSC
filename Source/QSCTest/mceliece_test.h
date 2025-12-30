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

#ifndef QSCTEST_MCELIECE_TEST_H
#define QSCTEST_MCELIECE_TEST_H

#include "qsctestcommon.h"

/**
 * \file mceliece_test.h
 * \brief McEliece Test Functions.
 *
 * \details
 * This source file contains tests for the McEliece implementation, including both Known Answer Tests (KATs)
 * and stress tests. The tests verify the correctness of key generation, encryption (encapsulation),
 * decapsulation, and the integrity of keys and ciphertext.
 *
 * The test suite includes:
 *
 * - A ciphertext integrity test that ensures a mutated ciphertext fails decapsulation and does not yield
 *   the expected shared secret.
 *
 * - A known answer test (KAT) that compares the generated public key, private key, ciphertext, and derived
 *   shared secret against expected values from the NIST PQC Round 3 test vectors.
 *
 * - A stress test that exercises the key generation, encapsulation, and decapsulation operations, including
 *   an alternate encrypt/decrypt API.
 *
 * - A public key integrity test that verifies that altering the public key results in an invalid shared secret.
 * 
 * \section mceliece_test_links Reference Links:
 * - <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions">NIST PQC Round 3 test vectors</a>
 */

/**
 * \brief Tests the integrity of a mutated McEliece ciphertext.
 *
 * \details
 * This test generates a McEliece key pair and encapsulates a shared secret, then deliberately mutates the
 * ciphertext by replacing some of its bytes with random data. It then attempts to decapsulate the modified
 * ciphertext and checks that:
 * - Decapsulation fails.
 * - The derived shared secret from the failed decapsulation does not match the expected shared secret.
 *
 * \return Returns true if the mutated ciphertext is correctly detected as invalid; otherwise, false.
 */
bool qsctest_mceliece_ciphertext_integrity(void);

/**
 * \brief Performs the McEliece Known Answer Test (KAT).
 *
 * \details
 * This function verifies the correctness of the McEliece implementation by comparing the generated public key,
 * private key, ciphertext, and shared secret with known answer test vectors from the NIST PQC Round 3 test files.
 * It:
 * - Parses the KAT file corresponding to the active parameter set.
 * - Generates a key pair and compares the keys to the expected values.
 * - Encapsulates a shared secret and compares the ciphertext and shared secret to the known answers.
 * - Decapsulates the ciphertext and verifies that the derived shared secret matches the expected value.
 *
 * \return Returns true if all generated values match the known answer test vectors; otherwise, false.
 */
bool qsctest_mceliece_kat_test(void);

/**
 * \brief Stress tests the McEliece operations.
 *
 * \details
 * This function performs a stress test on the McEliece key encapsulation mechanism by:
 * - Generating a key pair.
 * - Encapsulating a shared secret to produce a ciphertext and shared secret.
 * - Decapsulating the ciphertext to derive the shared secret.
 * - Verifying that the shared secrets obtained from encapsulation and decapsulation are identical.
 * - Exercising an alternate encrypt/decrypt API to confirm consistent behavior.
 *
 * \return Returns true if all operations produce matching shared secrets; otherwise, false.
 */
bool qsctest_mceliece_operations_test(void);

/**
 * \brief Tests the integrity of an altered McEliece public key.
 *
 * \details
 * This test generates a McEliece key pair and then alters the public key by replacing a portion of its bytes
 * with random values. It then performs encapsulation using the tampered public key and attempts decapsulation
 * with the valid secret key. The test passes if the derived shared secret is invalid, confirming that the altered
 * public key does not yield the expected result.
 *
 * \return Returns true if the tampered public key causes the shared secret to be invalid; otherwise, false.
 */
bool qsctest_mceliece_publickey_integrity(void);

/**
 * \brief Runs the full suite of McEliece tests.
 *
 * \details
 * This function sequentially executes all McEliece tests, including:
 * - The Known Answer Test (KAT) for verifying key generation, encryption (encapsulation), and decryption (decapsulation).
 * - The operations stress test for repeated key generation and shared secret derivation.
 * - The public key integrity test to ensure that altering the public key invalidates the derived shared secret.
 * - The ciphertext integrity test to confirm that tampering with the ciphertext is detected.
 *
 * Results from each test are printed to the console.
 */
void qsctest_mceliece_run(void);


#endif
