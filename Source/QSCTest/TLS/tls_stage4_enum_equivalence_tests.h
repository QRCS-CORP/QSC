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

#ifndef QSCTEST_TLS_STAGE4_ENUM_EQUIVALENCE_TESTS_H
#define QSCTEST_TLS_STAGE4_ENUM_EQUIVALENCE_TESTS_H

#include "../qsctestcommon.h"

/**
 * \file tls_stage4_enum_equivalence_tests.h
 * \brief Defines the TLS Stage 4 enumeration equivalence regression tests.
 *
 * \details This header declares the Stage 4 TLS regression test entry point and
 * the internal helper used to validate that the QSC TLS enumeration values
 * remain numerically aligned with the protocol constants mandated by RFC 8446
 * and the associated IANA registries. The implementation is primarily a
 * compile-time conformance gate; if an enumeration value drifts, compilation of
 * the corresponding test translation unit fails.
 */

/**
 * \brief Executes the TLS Stage 4 enumeration equivalence regression test.
 *
 * \details This routine invokes the Stage 4 enumeration equivalence gate and
 * reports the result through the QSC test harness output functions. The test is
 * successful when the implementation translation unit compiles with all static
 * equivalence assertions satisfied and the helper returns true.
 *
 * \return Returns true if the Stage 4 enumeration equivalence test succeeds.
 * Returns false if the test fails.
 */
bool qsctest_tls_stage4_tests(void);

/**
 * \brief Validates TLS enumeration to protocol constant equivalence.
 *
 * \details This helper represents the executable portion of the Stage 4 test.
 * The substantive validation is performed by compile-time assertions in the
 * implementation file. Successful compilation indicates that the checked QSC
 * TLS enumeration values match the required wire-format numeric constants.
 *
 * \return Returns true if the executable portion of the test succeeds.
 * Returns false on failure.
 */
bool qsctest_tls_stage4_enum_equivalence(void);

#endif
