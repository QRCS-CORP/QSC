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

#ifndef QSCTEST_ECDSA_TEST_H
#define QSCTEST_ECDSA_TEST_H

#include "common.h"

/**
 * \file ecdsa_test.h
 * \brief ECDSA test functions.
 *
 * \details
 * This header defines functions for testing the ECDSA (Elliptic Curve Digital Signature Algorithm)
 * implementation. The test suite includes the following:
 *
 * - A known answer test (KAT) that validates key generation, message signing, and signature verification
 *   using predetermined test vectors for messages of various lengths (32, 64, 96, and 128 bytes). This test
 *   ensures that the generated keys and signatures match the expected outputs.
 *
 * - A private key integrity test that deliberately mutates the secret key and verifies that the resulting
 *   signature fails verification, confirming that any alteration in the secret key is detected.
 *
 * - A public key integrity test that modifies a bit in the public key to ensure that signature verification
 *   fails when the public key has been tampered with.
 *
 * - A signature integrity test that flips bits in the generated signature (including parts of the hashed value)
 *   to verify that even minor modifications cause the verification to fail.
 *
 * - A stress test that repeatedly generates key pairs, signs a message, and verifies the signature over many
 *   iterations (as defined by QSCTEST_ECDSA_ITERATIONS) to assess the robustness and reliability of the implementation.
 *
 * These tests collectively ensure both the correctness and resilience of the ECDSA implementation.
 */

/**
 * \def QSCTEST_ECDSA_ITERATIONS
 * \brief Number of iterations to perform in the ECDSA stress test.
 *
 * When compiled in debug mode (_DEBUG defined), the number of iterations is set to 10.
 * Otherwise, it is set to 100.
 */
#ifdef _DEBUG
#   define QSCTEST_ECDSA_ITERATIONS 10
#else
#   define QSCTEST_ECDSA_ITERATIONS 100
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
 * \brief Test the ECDSA known answer test vectors.
 *
 * This function tests key generation, message signing, and signature verification against
 * predetermined test vectors for messages of varying lengths. It ensures that the generated public
 * and private keys and the produced signatures match the expected values.
 *
 * \return Returns true if all known answer tests pass.
 */
bool qsctest_ecdsa_kat_test(void);

/**
 * \brief Test the validity of a mutated secret key.
 *
 * This function deliberately alters a portion of the private key and attempts to sign a message.
 * The test passes only if the signature verification fails, indicating that any modification to the secret key
 * is correctly detected.
 *
 * \return Returns true if the test is successful.
 */
bool qsctest_ecdsa_privatekey_integrity(void);

/**
 * \brief Test the validity of a mutated public key.
 *
 * This function mutates the public key and verifies that signature verification fails when using the
 * altered public key.
 *
 * \return Returns true if the test is successful.
 */
bool qsctest_ecdsa_publickey_integrity(void);

/**
 * \brief Test the validity of a mutated signature.
 *
 * This function tests signature sensitivity by flipping bits in the signature. It verifies that even minor
 * alterations cause the signature verification to fail.
 *
 * \return Returns true if the test is successful.
 */
bool qsctest_ecdsa_signature_integrity(void);

/**
 * \brief Stress test the key generation, signing, and verification operations.
 *
 * This function performs a series of iterations (defined by QSCTEST_ECDSA_ITERATIONS) where a message is signed,
 * and the resulting signature is verified. It also checks that the signature length and the recovered message
 * remain correct in every iteration.
 *
 * \return Returns true if all stress tests pass.
 */
bool qsctest_ecdsa_stress_test(void);

/**
 * \brief Run the ECDSA implementation stress and correctness tests.
 *
 * This function executes the known answer tests, the integrity tests for keys and signature,
 * and the stress test, printing the result of each test to the console.
 */
void qsctest_ecdsa_run(void);

#endif
