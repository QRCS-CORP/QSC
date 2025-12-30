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

#ifndef QSCTEST_DILITHIUM_TEST_H
#define QSCTEST_DILITHIUM_TEST_H

#include "qsctestcommon.h"

/*!
 * \def QSCTEST_DILITHIUM_TEST_COUNT
 * \brief The number of Dilithium KAT tests.
 */
#define QSCTEST_DILITHIUM_TEST_COUNT 10U

/*!
 * \def QSCTEST_DILITHIUM_FULL_KAT
 * \brief Run the full Dilithium KAT tests.
 */
#define QSCTEST_DILITHIUM_FULL_KAT

/**
 * \file dilithium_test.h
 * \brief Dilithium Test Suite for the Digital Signature Scheme.
 *
 * \details
 * This header defines a set of tests for the Dilithium digital signature scheme implementation.
 * The test suite is designed to verify the correct operation of the Dilithium scheme by performing the following:
 *
 * - **Known Answer Test (KAT)**:  
 *   Validates key pair generation, signing, and signature verification using expected test vectors from the
 *   NIST Dilithium FIPS 204 specification. It confirms that the generated public key, secret key, signature, and recovered
 *   message exactly match the expected values.
 *
 * - **Secret Key Integrity Test**:  
 *   Intentionally mutates a portion of the secret key (by flipping bits) to verify that any tampering with
 *   the secret key results in a failure of signature verification.
 *
 * - **Public Key Integrity Test**:  
 *   Alters bits in the public key and ensures that signature verification fails, confirming that any corruption
 *   in the public key is reliably detected.
 *
 * - **Signature Integrity Test**:  
 *   Modifies the signature by flipping one or more bits and then checks that signature verification fails.
 *
 * - **Stress Test**:  
 *   Repeatedly generates key pairs, signs a fixed-length test message, and verifies the signature to ensure robust
 *   operation under extended use. This test also verifies that the signature length and the recovered message are as expected.
 *
 * The known answer test uses one of the NIST FIPS 204 test vector files, selected based on the active parameter set:
 * - If `QSC_DILITHIUM_S1P44` is defined, the file `"NPQC/dilithium-2544.rsp"` is used.
 * - If `QSC_DILITHIUM_S3P65` is defined, the file `"NPQC/dilithium-4016.rsp"` is used.
 * - If `QSC_DILITHIUM_S5P87` is defined, the file `"NPQC/dilithium-4880.rsp"` is used.
 *
 * \section dilithium_test_links Reference Links
 * - <a href="https://csrc.nist.gov/pubs/fips/204/final">NIST Dilithium FIPS 204 Main page</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf">NIST Dilithium FIPS 204 Specification</a>
 */

/**
 * \def QSCTEST_DILITHIUM_MLEN
 * \brief Length (in bytes) of the test message used in Dilithium tests.
 *
 * This macro defines the size of the test message. It is set to 33 bytes.
 */
#define QSCTEST_DILITHIUM_MLEN 33

/**
 * \brief Executes the known answer test (KAT) for the Dilithium signature scheme.
 *
 * \details
 * This test performs the following steps:
 * - Parses the NIST FIPS 204 test vector file to retrieve the expected seed, message, public key, secret key, and signature.
 * - Initializes a NIST-compliant PRNG using the extracted seed.
 * - Generates a key pair using the PRNG.
 * - Compares the generated public and secret keys with the expected values.
 * - Signs the fixed test message using the generated secret key.
 * - Compares the resulting signature with the expected signature.
 * - Verifies the signature using the generated public key and ensures that the recovered message matches the original.
 *
 * \return Returns true if the generated keys, signature, and recovered message match the expected test vectors.
 */
bool qsctest_dilithium_kat_test(void);

/**
 * \brief Tests the integrity of a mutated secret key.
 *
 * \details
 * This test deliberately flips bits in the secret key (specifically, in the portion following the public key)
 * and then attempts to sign a test message. The test is considered successful if signature verification fails,
 * indicating that any alteration of the secret key is correctly detected.
 *
 * \return Returns true if the signature verification fails when the secret key is altered.
 */
bool qsctest_dilithium_privatekey_integrity(void);

/**
 * \brief Tests the integrity of a mutated public key.
 *
 * \details
 * This test flips bits in the public key and then attempts to verify a signature produced with the unaltered secret key.
 * The test passes if the signature verification fails, confirming that any tampering with the public key is reliably detected.
 *
 * \return Returns true if signature verification fails when the public key is modified.
 */
bool qsctest_dilithium_publickey_integrity(void);

/**
 * \brief Tests the integrity of a mutated signature.
 *
 * \details
 * This test modifies the signature by flipping one or more bits (e.g., the last byte or a byte in the middle)
 * and then attempts to verify the signature against the original public key. The test passes if the altered signature
 * fails verification.
 *
 * \return Returns true if the signature verification fails with the modified signature.
 */
bool qsctest_dilithium_signature_integrity(void);

/**
 * \brief Performs a stress test on Dilithium key generation, signing, and verification operations.
 *
 * \details
 * This function repeatedly (in a single execution) performs the following:
 * - Generates a key pair.
 * - Signs a fixed test message of length QSCTEST_DILITHIUM_MLEN bytes.
 * - Verifies the signature and checks that the signature length is as expected.
 * - Confirms that the message recovered from the signature matches the original test message.
 *
 * The stress test is designed to assess the robustness and performance of the Dilithium implementation under extended use.
 *
 * \return Returns true if all stress test operations are successful.
 */
bool qsctest_dilithium_stress_test(void);

/**
 * \brief Runs all Dilithium test functions.
 *
 * \details
 * This function sequentially executes all tests for the Dilithium signature scheme, including:
 * - The known answer test (KAT) to verify key generation, signing, and verification against expected test vectors.
 * - The secret key integrity test, which ensures that modifications to the secret key result in verification failure.
 * - The public key integrity test, which ensures that modifications to the public key result in verification failure.
 * - The signature integrity test, which confirms that even minor changes to the signature cause verification to fail.
 * - A stress test that validates the robustness of the key generation, signing, and verification operations over multiple iterations.
 *
 * Test results are printed to the console.
 */
void qsctest_dilithium_run(void);

#endif
