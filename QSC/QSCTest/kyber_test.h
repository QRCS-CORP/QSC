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

#ifndef QSCTEST_KYBER_TEST_H
#define QSCTEST_KYBER_TEST_H

#include "common.h"
#include "../QSC/common.h"

/**
 * \file kyber_test.h
 * \brief Kyber Test Functions.
 *
 * \details
 * This file contains tests for the Kyber key encapsulation mechanism (KEM) implementation
 * as specified in the NIST FIPS 203 specification. The test suite includes:
 *
 * - A Known Answer Test (KAT) that verifies the generated public and private keys, the ciphertext,
 *   and the derived shared secret against expected test vectors.
 *
 * - A ciphertext integrity test that ensures that modifying the ciphertext results in an invalid shared secret.
 *
 * - A stress test that repeatedly generates key pairs, encapsulates, and decapsulates to verify that both
 *   parties derive the same shared secret.
 *
 * - Integrity tests that check whether altering the secret key or public key causes the derived shared secret
 *   to differ from the expected result.
 *
 * \section kyber_test_links Reference Links
 * - <a href="https://csrc.nist.gov/pubs/fips/203/final">NIST Kyber FIPS 203 Main page</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf">NIST Kyber FIPS 203 Specification</a>
 */

/*!
 * \def QSC_KYBER_TEST_COUNT
 * \brief The number of Kyber KAT tests.
 */
#define QSCTEST_KYBER_FULL_KAT

/*!
 * \def QSCTEST_KYBER_TEST_COUNT
 * \brief The number of Kyber KAT tests.
 */
#if defined(QSC_KYBER_FIPS203)
#	define QSCTEST_KYBER_TEST_COUNT 10ULL
#else
#	if defined(QSC_KYBER_S6P3936)
#	define QSCTEST_KYBER_TEST_COUNT 10ULL
#	else
#	define QSCTEST_KYBER_TEST_COUNT 100ULL
#	endif
#endif

/**
 * \brief Tests the validity of a mutated ciphertext.
 *
 * \details
 * This function generates a Kyber key pair and encapsulates a shared secret, then intentionally mutates the
 * ciphertext using random data. It attempts to decapsulate the altered ciphertext. The test passes if
 * decapsulation fails and the derived shared secret does not match the expected shared secret.
 *
 * \return Returns true if the mutated ciphertext is correctly detected as invalid; otherwise, false.
 */
bool qsctest_kyber_ciphertext_integrity(void);

/**
 * \brief Performs the Kyber Known Answer Test (KAT).
 *
 * \details
 * This function verifies the correctness of the Kyber implementation by comparing the generated public key,
 * secret key, ciphertext, and shared secret with known answer test vectors from the NIST FIPS 203 test files.
 * It parses the test vectors from the appropriate response file based on the active parameter set and compares
 * them against the output produced by the Kyber key encapsulation mechanism.
 *
 * \return Returns true if all generated values match the known answer test vectors; otherwise, false.
 */
bool qsctest_kyber_kat_test(void);

/**
 * \brief Performs a stress test on Kyber operations.
 *
 * \details
 * This function tests the key generation, encapsulation, and decapsulation operations of the Kyber KEM.
 * It first generates a key pair, then encapsulates a shared secret, and decapsulates it.
 * The test also exercises an alternate encrypt/decrypt API by clearing buffers and using a different interface.
 * The test passes if the shared secrets derived from encapsulation and decapsulation match.
 *
 * \return Returns true if all operations yield the expected shared secret; otherwise, false.
 */
bool qsctest_kyber_operations_test(void);

/**
 * \brief Tests the integrity of an altered Kyber secret key.
 *
 * \details
 * This test generates a Kyber key pair and encapsulates a shared secret. It then intentionally alters a portion
 * of the secret key with random data and attempts to decapsulate the ciphertext using the modified key.
 * The test is successful if decapsulation fails and the derived shared secret does not match the expected value.
 *
 * \return Returns true if the invalid secret key is correctly detected; otherwise, false.
 */
bool qsctest_kyber_privatekey_integrity(void);

/**
 * \brief Tests the integrity of an altered Kyber public key.
 *
 * \details
 * This function generates a Kyber key pair and then replaces part of the public key with random values.
 * It then encapsulates a shared secret using the altered public key and attempts decapsulation using the valid secret key.
 * The test passes if decapsulation fails and the derived shared secret does not match the expected result.
 *
 * \return Returns true if the invalid public key is correctly detected; otherwise, false.
 */
bool qsctest_kyber_publickey_integrity(void);

/**
 * \brief Runs all Kyber implementation tests.
 *
 * \details
 * This function sequentially executes the following tests:
 * - The Known Answer Test (KAT) to verify key generation and shared secret derivation.
 * - A stress test for key generation, encapsulation, and decapsulation.
 * - The secret key integrity test, ensuring that modifications to the secret key invalidate the shared secret.
 * - The public key integrity test, ensuring that alterations to the public key result in decapsulation failure.
 * - The ciphertext integrity test, confirming that tampered ciphertext leads to an invalid shared secret.
 *
 * The results of each test are printed to the console.
 */
void qsctest_kyber_run(void);


#endif
