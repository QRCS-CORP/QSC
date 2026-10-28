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
 * \brief HQC tests for the 2026-10-12 specification, all three parameter sets.
 *
 * \details
 * Local deterministic output digests test regression consistency and cross-backend
 * agreement. They are NOT official 2026 upstream Known Answer Tests.
 * The legacy HQC-2321/4602/7333 response files are incompatible with this version.
 * The remaining tests cover repeated operations and implicit rejection of altered keys
 * and ciphertexts. A distinct upstream KAT qualification remains necessary.
 */

#if defined(QSC_DEBUG_MODE)
	/*!
	 * \def QSCTEST_HQC_TEST_COUNT
	 * \brief Number of HQC operations test repetitions.
	 */
#	define QSCTEST_HQC_TEST_COUNT 10U
#else
	/*!
	 * \def QSCTEST_HQC_TEST_COUNT
	 * \brief Number of HQC operations test repetitions.
	 */
#	define QSCTEST_HQC_TEST_COUNT 100U
#endif

/**
 * \brief Verify altered ciphertexts produce a different implicit-rejection secret.
 * \return True if the rejection secret differs and decapsulation completes.
 */
bool qsctest_hqc_ciphertext_integrity(void);

/**
 * \brief Verify deterministic HQC-2026 QSC-local regression SHA3-256 digests.
 * \details This is not an independent or official upstream KAT.
 * \return True if private-key compression and reference regression digests match.
 */
bool qsctest_hqc_kat_test(void);

/**
 * \brief Repeat real key generation, encapsulation, and decapsulation operations.
 * \return True if every generated shared secret agrees.
 */
bool qsctest_hqc_operations_test(void);

/**
 * \brief Verify that a bit-flipped 32-byte private seed changes the shared secret.
 * \return True if the altered seed cannot recover the original shared secret.
 */
bool qsctest_hqc_privatekey_integrity(void);

/**
 * \brief Verify public-key modification changes the decapsulated secret.
 * \return True if encapsulation with the altered key cannot recover the secret.
 */
bool qsctest_hqc_publickey_integrity(void);

/**
 * \brief Run each named HQC regression and integrity test sequentially.
 * \return No return value; the individual test functions report status.
 */
void qsctest_hqc_run(void);

/** \brief Run named HQC-1 seeded and rejection regression.
 * \return True when all cases for the parameter pass.
 */
bool qsctest_hqc1_parameter_test(void);

/** \brief Run named HQC-3 seeded and rejection regression.
 * \return True when all cases for the parameter pass.
 */
bool qsctest_hqc3_parameter_test(void);

/** \brief Run named HQC-5 seeded and rejection regression.
 * \return True when all cases for the parameter pass.
 */
bool qsctest_hqc5_parameter_test(void);

#endif
