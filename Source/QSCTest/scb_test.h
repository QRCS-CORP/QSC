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

#ifndef QSCTEST_SCB_TEST_H
#define QSCTEST_SCB_TEST_H

#include "qsccommon.h"

/**
 * \file scb_test.h
 * \brief SCB Known Answer Tests.
 *
 * \details
 * This header defines functions for testing the SCB (SHAKE Cost-Based KDF) implementation against known
 * answer test (KAT) vectors. The SCB tests verify that the key derivation function produces the expected
 * output when provided with fixed seed and input parameters. The test vectors are derived from the
 * authoritative CEX cryptographic library.
 *
 * The test suite includes:
 * - A KAT test for the SCB-256 variant that computes a 256-bit hash and compares it to the expected output.
 * - A KAT test for the SCB-512 variant that computes a 512-bit hash and compares it to the expected output.
 * - A macro defining the number of test cycles for any stress testing routines.
 */

/**
 * \def QSCTEST_SCB_TEST_CYCLES
 * \brief Number of test cycles to execute in SCB tests.
 *
 * This macro defines the number of iterations (100) for SCB-related stress tests.
 */
#define QSCTEST_SCB_TEST_CYCLES 100

/**
 * \brief Tests the SCB-256 Known Answer Test (KAT) vectors.
 *
 * \details
 * This function computes a 256-bit hash using the SCB implementation with a predetermined seed and input.
 * It then compares the computed hash against the expected known answer vector.
 *
 * \return Returns true if the computed hash matches the expected output; otherwise, false.
 */
bool qsctest_scb_256_kat(void);

/**
 * \brief Tests the SCB-512 Known Answer Test (KAT) vectors.
 *
 * \details
 * This function computes a 512-bit hash using the SCB implementation with a fixed seed and input.
 * The result is compared with the expected known answer vector to verify correctness.
 *
 * \return Returns true if the computed hash matches the expected output; otherwise, false.
 */
bool qsctest_scb_512_kat(void);

/**
 * \brief Runs all SCB tests.
 *
 * \details
 * This function executes the complete set of SCB tests, including both the SCB-256 and SCB-512 known
 * answer tests. It prints the results of each test to the console.
 */
void qsctest_scb_run(void);


#endif
