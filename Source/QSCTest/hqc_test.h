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

#ifndef QSCTEST_HQC_TEST_H
#define QSCTEST_HQC_TEST_H

#include "qsctestcommon.h"
#include "qsccommon.h"

/**
 * \file hqc_test.h
 * \brief HQC test functions.
 *
 * \details
 * This file contains tests for the HQC key encapsulation mechanism implementation.
 * The test suite includes:
 *
 * - A Known Answer Test (KAT) that verifies the generated public and private keys,
 *   the ciphertext, and the derived shared secret against the official HQC response files.
 *
 * - A ciphertext integrity test that ensures that modifying the ciphertext results in
 *   decapsulation failure or in a mismatched shared secret.
 *
 * - A stress test that repeatedly generates key pairs, encapsulates, and decapsulates
 *   to verify that both parties derive the same shared secret.
 *
 * - Integrity tests that check whether altering the secret key or public key causes the
 *   derived shared secret to differ from the expected result.
 */

#if defined(QSC_DEBUG_MODE)
	/*!
	 * \def QSCTEST_HQC_TEST_COUNT
	 * \brief The number of HQC KAT tests.
	 */
#	define QSCTEST_HQC_TEST_COUNT 10U
#else
	/*!
	 * \def QSCTEST_HQC_TEST_COUNT
	 * \brief The number of HQC KAT tests.
	 */
#	define QSCTEST_HQC_TEST_COUNT 100U
#endif

 /**
  * \brief Tests the validity of a mutated ciphertext.
  *
  * \details
  * This function generates a HQC key pair and encapsulates a shared secret, then intentionally mutates the
  * ciphertext using random data. It attempts to decapsulate the altered ciphertext. The test passes if
  * decapsulation fails and the derived shared secret does not match the expected shared secret.
  *
  * \return Returns true if the mutated ciphertext is correctly detected as invalid; otherwise, false.
  */
bool qsctest_hqc_ciphertext_integrity(void);

/**
 * \brief Performs the HQC Known Answer Test (KAT).
 *
 * \details
 * This function verifies the correctness of the HQC implementation by comparing the generated public key,
 * secret key, ciphertext, and shared secret with known answer test vectors from the HQC test files, 
 * available at: https://gitlab.com/pqc-hqc/hqc.
 * It parses the test vectors from the appropriate response file based on the active parameter set and compares
 * them against the output produced by the HQC key encapsulation mechanism.
 *
 * \return Returns true if all generated values match the known answer test vectors; otherwise, false.
 */
bool qsctest_hqc_kat_test(void);

/**
 * \brief Performs a stress test on HQC operations.
 *
 * \details
 * This function tests the key generation, encapsulation, and decapsulation operations of the HQC KEM.
 * It first generates a key pair, then encapsulates a shared secret, and decapsulates it.
 * The test also exercises an alternate encrypt/decrypt API by clearing buffers and using a different interface.
 * The test passes if the shared secrets derived from encapsulation and decapsulation match.
 *
 * \return Returns true if all operations yield the expected shared secret; otherwise, false.
 */
bool qsctest_hqc_operations_test(void);

/**
 * \brief Tests the integrity of an altered HQC secret key.
 *
 * \details
 * This test generates a HQC key pair and encapsulates a shared secret. It then intentionally alters a portion
 * of the secret key with random data and attempts to decapsulate the ciphertext using the modified key.
 * The test is successful if decapsulation fails and the derived shared secret does not match the expected value.
 *
 * \return Returns true if the invalid secret key is correctly detected; otherwise, false.
 */
bool qsctest_hqc_privatekey_integrity(void);

/**
 * \brief Tests the integrity of an altered HQC public key.
 *
 * \details
 * This function generates a HQC key pair and then replaces part of the public key with random values.
 * It then encapsulates a shared secret using the altered public key and attempts decapsulation using the valid secret key.
 * The test passes if decapsulation fails and the derived shared secret does not match the expected result.
 *
 * \return Returns true if the invalid public key is correctly detected; otherwise, false.
 */
bool qsctest_hqc_publickey_integrity(void);

/**
 * \brief Runs all HQC implementation tests.
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
void qsctest_hqc_run(void);

#endif
