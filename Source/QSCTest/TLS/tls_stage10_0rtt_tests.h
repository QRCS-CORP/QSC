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

#ifndef QSCTEST_TLS_STAGE10_0RTT_TESTS_H
#define QSCTEST_TLS_STAGE10_0RTT_TESTS_H

#include "../qsctestcommon.h"

/**
 * \file tls_stage10_0rtt_tests.h
 * \brief Defines the QSC TLS Stage 10 zero round-trip time test functions.
 *
 * \details This header declares the Stage 10 test entry point and the internal
 * test functions used to validate the TLS 1.3 pre-shared key early-secret
 * branch exercised by resumed zero round-trip time operation. The tests verify
 * RFC 8448 Section 4 early-secret, binder-key, binder, and client early
 * traffic secret derivations, confirm the early exporter derivation path, and
 * validate early_data extension encoding and decoding.
 */

/**
 * \brief Executes the TLS Stage 10 zero round-trip time test set.
 *
 * \details This function is the public entry point called by the main QSC TLS
 * test harness. The function executes the internal Stage 10 tests and reports
 * the pass or fail status of each test using the standard QSC test output
 * format.
 *
 * \return Returns true if all Stage 10 tests succeed.
 */
bool qsctest_tls_stage10_tests(void);

/**
 * \brief Validates the RFC 8448 zero round-trip time key schedule vectors.
 *
 * \details This test initializes the TLS 1.3 key schedule with the RFC 8448
 * resumed handshake pre-shared key, derives the early secret, resumption binder
 * key, pre-shared key binder, and client early traffic secret, and compares the
 * resulting values to the published RFC vectors.
 *
 * \return Returns true if the vector checks succeed.
 */
bool qsctest_tls_stage10_0rtt_rfc8448_vectors(void);

/**
 * \brief Validates the early exporter derivation path.
 *
 * \details This test derives the early exporter master secret from a valid
 * early-secret state and transcript hash and confirms that the derivation path
 * completes successfully.
 *
 * \return Returns true if the derivation succeeds.
 */
bool qsctest_tls_stage10_0rtt_early_exporter(void);

/**
 * \brief Validates early_data extension encoding and decoding.
 *
 * \details This test verifies the empty early_data extension encoding used in
 * ClientHello messages and the max_early_data_size form used in NewSessionTicket
 * messages.
 *
 * \return Returns true if the extension round-trip checks succeed.
 */
bool qsctest_tls_stage10_0rtt_early_data_extension(void);

#endif
