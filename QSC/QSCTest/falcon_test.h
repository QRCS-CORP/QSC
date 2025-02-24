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

#ifndef QSCTEST_FALCON_TEST_H
#define QSCTEST_FALCON_TEST_H

#include "common.h"

/**
 * \file falcon_test.h
 * \brief Falcon Test Functions.
 *
 * \details
 * This source file implements tests for the Falcon digital signature scheme.
 * The test suite includes:
 * - A known answer test that verifies the generated public key, secret key, signature, and recovered message
 *   against expected values from the NIST PQC Round 3 test vectors.
 * - A secret key integrity test that mutates the secret key and confirms that signature verification fails.
 * - A public key integrity test that mutates the public key and ensures that signature verification fails.
 * - A signature integrity test that alters the signature to verify that any modification invalidates the signature.
 * - Stress tests that repeatedly generate key pairs, sign messages, and verify the signatures over multiple iterations,
 *   including tests with both fixed and random message lengths.
 *
 * \note The test message length used in several tests is defined by QSCTEST_FALCON_MLEN.
 *
 * \section falcon_test_links Reference Links:
 * - <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/round-3-submissions">NIST PQC Round 3 test vectors</a>
 */

/**
 * \def QSCTEST_FALCON_MLEN
 * \brief Fixed message length for Falcon tests.
 *
 * This macro defines the message length (33 bytes) used in the Falcon tests.
 */
#define QSCTEST_FALCON_MLEN 33

/**
 * \brief Performs the Falcon known answer test.
 *
 * \details
 * This function tests the Falcon digital signature scheme against known answer test (KAT) vectors
 * from the NIST PQC Round 3 submissions. It:
 * - Parses a KAT file (either "NPQCR3/falcon512.rsp" or "NPQCR3/falcon1024.rsp", depending on the parameter set)
 *   to obtain the expected seed, message, public key, secret key, and signature.
 * - Initializes a NIST-compliant PRNG with the test seed.
 * - Generates a key pair and compares the generated public and private keys to the expected values.
 * - Signs the test message and compares the resulting signature with the expected signature.
 * - Verifies the signature and ensures that the recovered message matches the original.
 *
 * \return Returns true if all comparisons succeed; otherwise, false.
 */
bool qsctest_falcon_operations_test(void);

/**
 * \brief Tests the integrity of a mutated Falcon secret key.
 *
 * \details
 * This test generates a Falcon key pair and then deliberately flips bits in the secret key.
 * It signs a test message using the altered secret key and verifies that the signature verification fails.
 *
 * \return Returns true if the verification fails as expected with an altered secret key.
 */
bool qsctest_falcon_privatekey_integrity(void);

/**
 * \brief Tests the integrity of a mutated Falcon public key.
 *
 * \details
 * This test generates a Falcon key pair, mutates the public key by flipping bits, and then signs a test message
 * using the valid secret key. The test passes if signature verification fails when using the altered public key.
 *
 * \return Returns true if the altered public key causes signature verification to fail.
 */
bool qsctest_falcon_publickey_integrity(void);

/**
 * \brief Tests the integrity of a mutated Falcon signature.
 *
 * \details
 * This function signs a test message using a valid Falcon key pair, then modifies the signature by flipping one or more bits.
 * It verifies that the altered signature does not pass verification.
 *
 * \return Returns true if the signature verification fails for the mutated signature.
 */
bool qsctest_falcon_signature_integrity(void);

/**
 * \brief Performs a stress test on Falcon operations with a fixed message length.
 *
 * \details
 * This test repeatedly (over many iterations) performs the following:
 * - Generates a Falcon key pair.
 * - Signs a fixed-length test message.
 * - Verifies that the signature is valid and that the recovered message matches the original.
 * It also checks that the signature length is as expected.
 *
 * \return Returns true if all iterations of the stress test pass; otherwise, false.
 */
bool qsctest_falcon_stress_test(void);

/**
 * \brief Performs an additional stress test on Falcon operations with random message lengths.
 *
 * \details
 * This function iterates 10 times, each time:
 * - Generating a random message length.
 * - Allocating and filling a message with random data.
 * - Generating a Falcon key pair.
 * - Signing the random message and verifying that the signature is valid and that the recovered message
 *   matches the original.
 *
 * \return Returns true if all iterations pass; otherwise, false.
 */
bool qsctest_falcon_stress_test2(void);

/**
 * \brief Runs the complete Falcon test suite.
 *
 * \details
 * This function sequentially executes all Falcon tests, including:
 * - The known answer test (operations test)
 * - The secret key integrity test
 * - The public key integrity test
 * - The signature integrity test
 * - The stress tests
 *
 * The results of each test are printed to the console.
 */
void qsctest_falcon_run(void);


#endif
