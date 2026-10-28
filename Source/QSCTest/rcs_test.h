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

#ifndef QSCTEST_RCS_TEST_H
#define QSCTEST_RCS_TEST_H

#include "qsctestcommon.h"
#include "rcs.h"

/**
 * \file rcs_test.h
 * \brief RCS Known Answer Tests.
 *
 * \details
 * This header exposes the existing QSCTEST RCS-256 and RCS-512 KAT and
 * stress-test entry points. Each KAT entry point directly executes TEN frozen
 * original-source vectors. The active profile is selected at compile time:
 *  - default: RCS-256 14 rounds / RCS-512 21 rounds;
 *  - QSC_RCS_EXTENDED_ROUND_COUNTS: RCS-256 22 / RCS-512 30 rounds.
 * Both profiles authenticate using 24-round Keccak/KMAC. Each vector verifies
 * two chained authenticated ciphertexts/tags, final nonce, decryption and tag
 * rejection; the frozen fixtures do not depend on files at test runtime.
 *
 * Reference provenance: original QRCS RCS reference source, as documented in
 * Qualification/RCS/RCS_ROUND_POLICY_AND_KAT_QUALIFICATION.md. The default
 * vectors required the single documented 12-to-24 Keccak-round selection.
 * The stress-test APIs and original test runner are retained.
 *
 * \section rcs_kat_links Reference Links
 * - CEX Cryptographic Library: <a href="https://github.com/Steppenwolfe65/CEX">CEX</a>
 * - CEX RCS Tests: <a href="https://github.com/Steppenwolfe65/CEX/blob/master/Test/RCSTest.cpp">RCSTest.cpp</a>
 */

#if defined(QSC_SYSTEM_HAS_AVX512)
#	if defined(QSC_SYSTEM_AESNI_ENABLED)
#		if !defined(QSC_RCS_AUTHENTICATED)
#			define QSCTEST_RCS_WIDE_BLOCK_TESTS
#		endif
#	endif
#endif

/**
 * \def QSCTEST_RCS_TEST_CYCLES
 * \brief Number of iterations for RCS stress tests.
 *
 * This macro defines the number of test iterations (100) used in the RCS stress tests.
 */
#define QSCTEST_RCS_TEST_CYCLES 100

/**
 * \brief Verifies ten RCS-256 authoritative KAT vectors for the selected round profile.
 *
 * \details
 * Uses ten frozen original-source ciphertext/tag and nonce expectations with
 * deterministic keys, messages, AAD, tweak and nonce. Includes decryption and tag rejection.
 *
 * \return Returns true if the RCS-256 KAT test passes; otherwise, false.
 */
bool qsctest_rcs256_kat(void);

/**
 * \brief Verifies ten RCS-512 authoritative KAT vectors for the selected round profile.
 *
 * \details
 * Uses ten frozen original-source ciphertext/tag and nonce expectations with
 * deterministic keys, messages, AAD, tweak and nonce. Includes decryption and tag rejection.
 *
 * \return Returns true if the RCS-512 KAT test passes; otherwise, false.
 */
bool qsctest_rcs512_kat(void);

/**
 * \brief Stress tests the RCS-256 implementation with random inputs.
 *
 * \details
 * This function performs a stress test on the RCS-256 algorithm by encrypting and decrypting randomly
 * generated messages over a number of iterations defined by QSCTEST_RCS_TEST_CYCLES. It verifies that the
 * decrypted output matches the original input.
 *
 * \return Returns true if all RCS-256 stress test iterations pass; otherwise, false.
 */
bool qsctest_rcs256_stress_test(void);

/**
 * \brief Stress tests the RCS-512 implementation with random inputs.
 *
 * \details
 * This function repeatedly encrypts and decrypts randomly generated messages using the RCS-512 algorithm,
 * verifying that the output is consistent with the original input.
 *
 * \return Returns true if the RCS-512 stress test passes; otherwise, false.
 */
bool qsctest_rcs512_stress_test(void);

/**
 * \brief Tests the extended transform API of the RCS implementation.
 *
 * \details
 * This function validates the extended API for RCS, ensuring that the output produced by this API
 * matches the expected result.
 *
 * \return Returns true if the extended transform API test passes; otherwise, false.
 */
bool qsctest_extended_cipher_test(void);

#if defined(QSCTEST_RCS_WIDE_BLOCK_TESTS)
/**
 * \brief Tests the RCS AVX functions for equality with sequential processing.
 *
 * \details
 * When wide block tests are enabled, this function checks that the AVX-accelerated RCS transform produces
 * output identical to that of the sequential (non-AVX) implementation.
 *
 * \return Returns true if the outputs are equal; otherwise, false.
 */
bool qsctest_rcs_wide_equality(void);
#endif

/**
 * \brief Runs all RCS test functions.
 *
 * \details
 * This function executes the full suite of RCS tests, including:
 * - Ten independent frozen KAT cases for RCS-256.
 * - Ten independent frozen KAT cases for RCS-512.
 * - The existing RCS-256 and RCS-512 randomized stress tests.
 *
 * Test results are printed to the console.
 */
void qsctest_rcs_run(void);


#endif
