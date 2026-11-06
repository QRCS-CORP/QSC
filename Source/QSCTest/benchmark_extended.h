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
#ifndef QSCTEST_BENCHMARK_EXTENDED_H
#define QSCTEST_BENCHMARK_EXTENDED_H

#include "qsctestcommon.h"

/*! \file benchmark_extended.h
 * \brief Runtime hardware assessment and classical/post-quantum benchmark entry points.
 * \details Benchmarks use the algorithms selected by the linked QSC build.
 */

/*! \brief Print host CPU/OS instruction availability and local compilation profile.
 * \details Read-only diagnostic; a separate linked QSC binary can have different build flags.
 */
void qsctest_benchmark_profile_run(void);

/*! \brief Measure selected ECDSA key generation, signing, and verification. */
void qsctest_benchmark_ecdsa_run(void);

/*! \brief Measure selected ECDH key generation and key agreement. */
void qsctest_benchmark_ecdh_run(void);

/*! \brief Measure selected EdDH key generation and key agreement. */
void qsctest_benchmark_eddh_run(void);

/*! \brief Measure selected EdDSA key generation, signing, and verification. */
void qsctest_benchmark_eddsa_run(void);

/*! \brief Measure selected ML-DSA key generation, signing, and verification. */
void qsctest_benchmark_mldsa_run(void);

/*! \brief Measure selected SLH-DSA key generation, signing, and verification. */
void qsctest_benchmark_slhdsa_run(void);

/*! \brief Measure selected ML-KEM key generation, encapsulation, and decapsulation. */
void qsctest_benchmark_mlkem_run(void);

/*! \brief Measure selected HQC key generation, encapsulation, and decapsulation. */
void qsctest_benchmark_hqc_run(void);

/*! \brief Print outcome counts and return aggregate asymmetric benchmark status.
 * \return True if all scheduled measurements and their preflight checks succeeded.
 */
bool qsctest_benchmark_extended_summary_run(void);

#endif
