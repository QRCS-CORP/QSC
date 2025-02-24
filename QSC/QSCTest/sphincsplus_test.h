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

#ifndef QSCTEST_SPHINCSPLUS_TEST_H
#define QSCTEST_SPHINCSPLUS_TEST_H

#include "common.h"

/**
 * \file sphincsplus_test.h
 * \brief SphincsPlus Test Functions.
 *
 * \details
 * This source file implements a comprehensive suite of tests for the SPHINCS+ post-quantum signature scheme.
 * These tests include known answer tests (KATs) and various integrity and stress tests designed to verify the
 * correctness and robustness of the SPHINCS+ implementation. In particular, the tests verify:
 *
 * - That the generated key pairs (public and secret keys) match the expected values from the NIST FIPS 205 test vectors.
 * - That the signature produced for a given message is exactly as expected.
 * - That signature verification recovers the original message correctly.
 * - That deliberate modifications to the secret key, public key, or signature result in a failed verification,
 *   thereby confirming the sensitivity of the algorithm to tampering.
 * - That the implementation withstands repeated use by performing a stress test over multiple iterations.
 *
 * Depending on compile-time configuration, the extended SPHINCS+ parameter set may be tested (when
 * QSC_SPHINCSPLUS_EXTENDED is defined), in which case an extended test function is provided.
 *
 * The functions in this file return a boolean value (true for success, false for failure) and print
 * diagnostic messages to the console.
 *
 * \note The default test message length is defined by the macro \c QSCTEST_SPHINCSPLUS_MLEN.
 *
 * \section sphincsplus_test_links Reference Links
 * - <a href="https://csrc.nist.gov/pubs/fips/205/final">NIST SPHINCS+ FIPS 205 Main page</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf">NIST SPHINCS+ FIPS 205 Specification</a>
 */

/*!
 * \def QSCTEST_SPHINCSPLUS_MLEN
 * \brief The test message byte size.
 */
#define QSCTEST_SPHINCSPLUS_MLEN 33

/**
 * \brief Tests the extended version of the SPHINCS+ signature scheme.
 *
 * \details
 * This function is enabled when the QSC_SPHINCSPLUS_EXTENDED macro is defined. It performs a full test of the
 * extended SPHINCS+ parameter set (typically corresponding to a 512-bit security level) by:
 * - Generating a key pair.
 * - Signing a test message.
 * - Verifying the signature.
 * - Checking that the signature length is as expected.
 * - Confirming that the recovered message matches the original.
 *
 * \return Returns true if the extended SPHINCS+ test passes; otherwise, returns false.
 */
bool qsctest_sphincsplus_extended_test(void);

#if !defined(QSC_SPHINCSPLUS_EXTENDED)

/**
 * \brief Tests SPHINCS+ operations against known answer test vectors.
 *
 * \details
 * This function verifies the basic operations of the SPHINCS+ signature scheme using the second test vector
 * from the NIST FIPS 205 KAT file. It performs the following steps:
 * - Parses the known answer test (KAT) vector to obtain expected values for the message, public key, secret key,
 *   and signature.
 * - Generates a new key pair.
 * - Signs the known message using the generated secret key.
 * - Verifies the resulting signature using the corresponding public key.
 * - Compares the generated public key, secret key, and signature with the known answer values.
 *
 * \return Returns true if all aspects of the test pass; otherwise, returns false.
 */
bool qsctest_sphincsplus_operations_test(void);

/**
 * \brief Tests the integrity of the SPHINCS+ secret key.
 *
 * \details
 * This function evaluates whether slight modifications to the secret key prevent proper signature verification.
 * It performs the following steps:
 * - Generates a SPHINCS+ key pair.
 * - Mutates (flips bits in) the secret key.
 * - Signs a test message with the altered secret key.
 * - Verifies that the signature verification fails when using the unmodified public key.
 *
 * \return Returns true if signature verification fails with a mutated secret key; otherwise, returns false.
 */
bool qsctest_sphincsplus_privatekey_integrity(void);

/**
 * \brief Tests the integrity of the SPHINCS+ public key.
 *
 * \details
 * This function ensures that a minor change in the public key results in a failure of signature verification.
 * It operates by:
 * - Generating a SPHINCS+ key pair.
 * - Mutating the public key (e.g. flipping a bit in the last byte).
 * - Signing a message using the valid secret key.
 * - Confirming that verification using the altered public key fails.
 *
 * \return Returns true if the altered public key leads to verification failure; otherwise, returns false.
 */
bool qsctest_sphincsplus_publickey_integrity(void);

/**
 * \brief Tests the integrity of the SPHINCS+ signature.
 *
 * \details
 * This function checks that any alteration to the generated signature renders it invalid. The process includes:
 * - Generating a key pair.
 * - Signing a test message.
 * - Mutating the signature by flipping one or more bits.
 * - Verifying that the altered signature does not validate.
 *
 * \return Returns true if the mutated signature fails to verify; otherwise, returns false.
 */
bool qsctest_sphincsplus_signature_integrity(void);

/**
 * \brief Performs a stress test of the SPHINCS+ signature scheme.
 *
 * \details
 * This function repeatedly generates key pairs, signs a fixed test message, and verifies the signature over
 * multiple iterations. It confirms that:
 * - The signature length remains consistent.
 * - The verification process correctly recovers the original message.
 * This stress test helps to ensure the robustness and efficiency of the implementation under heavy use.
 *
 * \return Returns true if all stress test iterations succeed; otherwise, returns false.
 */
bool qsctest_sphincsplus_stress_test(void);

#endif

/**
 * \brief Runs the SPHINCS+ test suite.
 *
 * \details
 * This function executes the complete suite of SPHINCS+ tests. When the extended mode is enabled
 * (QSC_SPHINCSPLUS_EXTENDED defined), it runs the extended tests. Otherwise, it runs the standard
 * tests which include:
 * - Operation tests (key generation, signing, and verification) against known answer test vectors.
 * - Integrity tests for the secret key, public key, and signature.
 * - A stress test to validate the scheme under repeated use.
 *
 * Test results are printed to the console.
 */
void qsctest_sphincsplus_run(void);

#endif
