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

/** \def QSCTEST_HCG_TEST_H
 * \brief Prevent multiple inclusions of the HCG test declarations.
 */
#ifndef QSCTEST_HCG_TEST_H
#define QSCTEST_HCG_TEST_H

#include "qsccommon.h"

/**
 * \file hcg_test.h
 * \brief HMAC_DRBG-SHA-512 known-answer, wellness, and deterministic fuzz tests.
 * \details Tests exercise the SP 800-90A Rev. 1 HCG API, including deterministic
 * generation with and without additional input, reseeding, ACVP-style prediction
 * resistance, ACP-backed operation, state lifetime, request bounds and randomized
 * input sequences. Reference KAT fixtures were independently produced with
 * Python HMAC-SHA-512; they are not official NIST/ACVP validation vectors.
 * Statistical wellness checks are gross-failure indicators, not entropy assessment
 * or proof of cryptographic security. The tests are sequential, non-concurrent.
 */

/** \brief Check deterministic instantiate and generate output against an independently calculated KAT. 
* \return True on success; false otherwise. 
*/
bool qsctest_hcg_basic_kat(void);

/** \brief Check personalization and two Generate operations with additional input. 
* \return True on success; false otherwise. 
*/
bool qsctest_hcg_additional_kat(void);

/** \brief Check explicit entropy reseeding and additional-input behavior. 
* \return True on success; false otherwise. 
*/
bool qsctest_hcg_reseed_kat(void);

/** \brief Check ACVP-style explicit reseed before Generate, modelling prediction resistance. 
* \return True on success; false otherwise. 
*/
bool qsctest_hcg_prediction_resistance_kat(void);

/** \brief Check minimum inputs, request/reseed limits, and state zeroization. 
* \return True on success; false otherwise. 
*/
bool qsctest_hcg_boundaries(void);

/** \brief Exercise ACP-backed instantiation, automatic reseeding, and prediction resistance. 
* \return True on success; false otherwise. \note Requires operational OS entropy, but does not validate entropy quality. 
*/
bool qsctest_hcg_auto_seed(void);

/** \brief Perform bounded output wellness checks (bit balance, histogram, repeated blocks, byte runs). 
* \return True on success; false otherwise. \note Does not constitute SP 800-90B or NIST STS certification. 
*/
bool qsctest_hcg_wellness(void);

/** \brief Verify state progression, legacy initialization, reseed reset, and maximum output request. 
* \return True on success; false otherwise. 
*/
bool qsctest_hcg_state_wellness(void);

/** \brief Execute 256 reproducible, randomized valid-operation sequences and consistency checks. 
* \return True on success; false otherwise. \note Uses a noncryptographic deterministic test-case generator. 
*/
bool qsctest_hcg_fuzz(void);

/** \brief Exercise 256 malformed requests and ensure no state advancement or buffer overwrite. 
* \return True on success; false otherwise. 
*/
bool qsctest_hcg_invalid_fuzz(void);

/** \brief Run every HCG KAT, wellness, boundary, ACP integration, and fuzz test sequentially. 
* \note Prints distinct PASS/FAIL outcomes and returns aggregate status to the caller. 
*/
void qsctest_hcg_run(void);

#endif
