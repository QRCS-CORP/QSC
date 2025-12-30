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

#ifndef QSCTEST_QMAC_TEST_H
#define QSCTEST_QMAC_TEST_H

#include "qsccommon.h"

/**
 * \file qmac_test.h
 * \brief QMAC Known Answer Tests.
 *
 * \details
 * This header defines functions for testing the QMAC implementation.
 * The QMAC tests verify that the MAC generator produces outputs that match the expected known
 * answer test vectors.
 *
 * The test suite includes:
 * - A compact API test that computes the MAC for various messages and keys, comparing the output
 *   against expected values.
 * - A long-form API test that uses incremental update and finalization calls to compute the MAC,
 *   verifying that the stateful interface yields the correct output.
 * - Tests that incorporate a nonce into the MAC computation to ensure proper handling of additional
 *   parameters.
 */

/**
 * \brief Tests the QMAC implementation against known answer test vectors.
 *
 * \details
 * This function computes the MAC for several test messages using different key and nonce values,
 * then compares the computed MACs to the expected known answer values.
 *
 * \return Returns true if all computed MACs match the expected outputs; otherwise, false.
 */
bool qsctest_qmac_kat(void);

/**
 * \brief Runs all QMAC tests.
 *
 * \details
 * This function executes the complete QMAC test suite, including both the compact API tests
 * and the long-form API tests. It prints the results of the tests to the console.
 */
void qsctest_qmac_run(void);

#endif
