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

#ifndef QSCTEST_ECDH_TEST_H
#define QSCTEST_ECDH_TEST_H

#include "qsctestcommon.h"

/**
 * \file ecdh_test.h
 * \brief ECDH P-256 test functions.
 *
 * \details
 * This header defines test functions for the NIST P-256 Elliptic Curve Diffie-Hellman
 * implementation exposed by ecdhbase256.h. The test suite includes:
 *
 * - Known answer tests derived from the official NIST CAVP ECC CDH Primitive vectors.
 * - A stress test that repeatedly generates key pairs and verifies shared-secret agreement.
 * - Integrity tests that mutate a private key or public key and verify that agreement fails
 *   or produces a different shared secret.
 * KAT file links:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors/KAS_ECC_CDH_PrimitiveTest.txt
 */

/**
 * \def QSCTEST_ECDH_ITERATIONS
 * \brief The number of iterations for the ECDH stress and integrity tests.
 */
#define QSCTEST_ECDH_ITERATIONS 100U

/**
 * \brief Performs the ECDH P-256 NIST known answer tests.
 *
 * \details
 * This test uses official NIST ECC CDH Primitive test vectors for curve P-256.
 * It verifies that:
 * - Public-key generation from dIUT matches QIUT.
 * - Shared-secret derivation using QCAVS matches ZIUT.
 *
 * \return Returns true on success.
 */
bool qsctest_ecdh_kat_test(void);

/**
 * \brief Performs a repeated ECDH P-256 operations test.
 *
 * \details
 * This test repeatedly generates two key pairs and confirms that both parties derive
 * the same shared secret.
 *
 * \return Returns true on success.
 */
bool qsctest_ecdh_operations_test(void);

/**
 * \brief Tests ECDH P-256 private-key integrity.
 *
 * \details
 * This test mutates a private key after key generation and confirms that agreement either
 * fails or no longer matches the unmodified peer result.
 *
 * \return Returns true on success.
 */
bool qsctest_ecdh_privatekey_integrity(void);

/**
 * \brief Tests ECDH P-256 public-key integrity.
 *
 * \details
 * This test mutates a public key after key generation and confirms that agreement either
 * fails or no longer matches the unmodified peer result.
 *
 * \return Returns true on success.
 */
bool qsctest_ecdh_publickey_integrity(void);

/**
 * \brief Runs the complete ECDH P-256 test suite.
 */
void qsctest_ecdh_run(void);

#endif
