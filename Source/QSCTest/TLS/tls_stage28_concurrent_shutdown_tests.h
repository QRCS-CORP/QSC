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
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
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

#ifndef QSCTEST_TLS_STAGE28_CONCURRENT_SHUTDOWN_TESTS_H
#define QSCTEST_TLS_STAGE28_CONCURRENT_SHUTDOWN_TESTS_H

#include "../qsctestcommon.h"

/**
 * \file tls_stage28_concurrent_shutdown_tests.h
 * \brief Defines the QSC TLS Stage 28 concurrent shutdown and worker cleanup tests.
 *
 * \details This header declares the public entry point for the Stage 28 TLS
 * concurrent server lifecycle test module. The implementation follows the QSC
 * TLS staged test reporting model and validates deterministic cleanup of the
 * fixed concurrent server pool, shutdown state flags, worker state records,
 * listener close state, max-client policy rejection while active slots exist,
 * and repeated stop/dispose behavior.
 */

/**
 * \brief Execute the TLS Stage 28 concurrent shutdown and worker cleanup test set.
 *
 * \details This function runs deterministic lifecycle tests that do not require
 * generated certificates or external socket peers. The tests exercise public TLS
 * socket server and listener cleanup semantics by constructing initialized server
 * states with active slots, started-slot markers, and retained worker metadata.
 * Live network accept-loop behavior is covered separately by end-to-end and
 * interoperability stages.
 *
 * \return Returns true if all Stage 28 tests succeed.
 */
bool qsctest_tls_stage28_tests(void);

#endif
