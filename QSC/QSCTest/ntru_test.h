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

#ifndef QSCTEST_NTRU_TEST_H
#define QSCTEST_NTRU_TEST_H

#include "common.h"

/**
 * \file ntru_test.h
 * \brief NTRU Test Functions.
 *
 * \details
 * This source file implements a test suite for the NTRU key encapsulation mechanism (KEM) implementation.
 * The tests verify the correctness, integrity, and resilience of the NTRU algorithm by performing the following:
 *
 * - **Ciphertext Integrity Test**:  
 *   The function \c qsctest_ntru_ciphertext_integrity() generates a NTRU key pair and encapsulates a shared secret.
 *   It then deliberately mutates the ciphertext using random data and attempts to decapsulate it. The test passes if
 *   decapsulation fails and the derived shared secret differs from the expected one.
 *
 * - **Known Answer Test (KAT)**:  
 *   The function \c qsctest_ntru_kat_test() parses known answer test vectors from a NIST PQC Round 3 response file,
 *   generates a key pair, encapsulates a shared secret, and verifies that the generated public key, private key,
 *   ciphertext, and shared secret match the expected values.
 *
 * - **Operations Stress Test**:  
 *   The function \c qsctest_ntru_operations_test() repeatedly generates key pairs, encapsulates a shared secret,
 *   and decapsulates the ciphertext to verify that the shared secret derived from encapsulation matches the one obtained
 *   via decapsulation. It also tests an alternate encrypt/decrypt API.
 *
 * - **Private Key Integrity Test**:  
 *   The function \c qsctest_ntru_privatekey_integrity() alters part of the secret key with random data and then checks
 *   that decapsulation fails, ensuring that an invalid secret key does not produce the expected shared secret.
 *
 * - **Public Key Integrity Test**:  
 *   The function \c qsctest_ntru_publickey_integrity() modifies the public key with random data and then verifies that
 *   decapsulation using the valid secret key fails, ensuring that tampering with the public key is detected.
 *
 * The function \c qsctest_ntru_run() executes all the tests sequentially and prints the results.
 */

/**
 * \brief Tests the integrity of a mutated NTRU ciphertext.
 *
 * \details
 * This test function performs the following steps:
 * - Generates a NTRU key pair.
 * - Encapsulates a shared secret using the generated public key.
 * - Mutates the resulting ciphertext by overwriting part of it with random data.
 * - Attempts to decapsulate the mutated ciphertext using the corresponding secret key.
 * The test is considered successful if decapsulation fails and the derived shared secret does not match the
 * originally encapsulated shared secret.
 *
 * \return Returns true if the ciphertext integrity check passes; otherwise, false.
 */
bool qsctest_ntru_ciphertext_integrity(void);

/**
 * \brief Performs the NTRU Known Answer Test (KAT).
 *
 * \details
 * This function verifies the correctness of the NTRU implementation by:
 * - Parsing a NIST PQC Round 3 KAT response file to obtain the expected seed, public key, private key,
 *   ciphertext, and shared secret.
 * - Initializing a PRNG with the parsed seed.
 * - Generating a NTRU key pair and comparing the generated keys with the expected ones.
 * - Encapsulating a shared secret and comparing the resulting ciphertext and shared secret against the expected values.
 * - Decapsulating the ciphertext and verifying that the shared secret derived matches both the encapsulated value
 *   and the known answer.
 *
 * \return Returns true if all generated values match the known answer test vectors; otherwise, false.
 */
bool qsctest_ntru_kat_test(void);

/**
 * \brief Stress tests NTRU operations.
 *
 * \details
 * This function conducts a stress test on the NTRU key encapsulation mechanism by:
 * - Generating a NTRU key pair.
 * - Encapsulating a shared secret to produce a ciphertext and shared secret.
 * - Decapsulating the ciphertext to derive the shared secret.
 * - Comparing the shared secrets obtained from encapsulation and decapsulation.
 * - Exercising an alternate encrypt/decrypt API by clearing buffers, generating a fresh seed,
 *   and verifying that the shared secrets produced by both interfaces are identical.
 *
 * \return Returns true if the shared secrets match and all operations are successful; otherwise, false.
 */
bool qsctest_ntru_operations_test(void);

/**
 * \brief Tests the integrity of an altered NTRU secret key.
 *
 * \details
 * This test generates a valid NTRU key pair and encapsulates a shared secret. It then alters the secret key
 * (by replacing a portion of it with random data) and attempts to decapsulate the previously produced ciphertext.
 * The test passes if decapsulation fails or the derived shared secret does not match the expected shared secret.
 *
 * \return Returns true if the secret key integrity test passes; otherwise, false.
 */
bool qsctest_ntru_privatekey_integrity(void);

/**
 * \brief Tests the integrity of an altered NTRU public key.
 *
 * \details
 * This function generates a NTRU key pair, then mutates the public key by overwriting some of its bytes with
 * random data. It encapsulates a shared secret using the tampered public key and attempts decapsulation using
 * the valid secret key. The test is successful if the shared secret derived from decapsulation is invalid.
 *
 * \return Returns true if the public key integrity test passes; otherwise, false.
 */
bool qsctest_ntru_publickey_integrity(void);

/**
 * \brief Runs the complete NTRU test suite.
 *
 * \details
 * This function executes all the NTRU tests, including:
 * - The Known Answer Test (KAT) to verify that key generation, encapsulation, and decapsulation produce expected values.
 * - The operations stress test to verify repeated key encapsulation and decapsulation.
 * - The private key integrity test to ensure that an altered secret key invalidates the shared secret.
 * - The public key integrity test to ensure that a tampered public key leads to decapsulation failure.
 * - The ciphertext integrity test to confirm that modified ciphertext does not yield the correct shared secret.
 *
 * Test results are printed to the console.
 */
void qsctest_ntru_run(void);


#endif
