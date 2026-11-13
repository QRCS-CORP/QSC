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

#ifndef QSCTEST_CSG_TEST_H
#define QSCTEST_CSG_TEST_H

#include "qsccommon.h"

/**
 * \file csg_test.h
 * \brief Candidate XDRBG-SHAKE-256 known-answer, wellness and fuzz testing.
 * \details Reference outputs are from the published XDRBG author KAT and
 * independently calculated deterministic SHAKE-256 fixtures. These are not
 * official SP 800-90A Revision 2 or ACVP vectors. Wellness tests detect gross
 * failures only and do not constitute SP 800-90B entropy assessment.
 * All tests execute sequentially and are not thread safe.
 */

/** \brief Check the published author short-seed reference SHAKE-256 calculation. 
* \return True on success, false otherwise. 
*/
bool qsctest_csg_author_kat(void);

/** \brief Check deterministic instantiate and two Generate operations. 
* \return True on success, false otherwise.
*/
bool qsctest_csg_generate_kat(void);

/** \brief Check personalization, explicit reseeding and additional input. 
* \return True on success, false otherwise.
*/
bool qsctest_csg_reseed_kat(void);

/** \brief Check 84-byte additional input and 344-byte request limits. 
* \return True on success, false otherwise. 
*/
bool qsctest_csg_maximum_kat(void);

/** \brief Check malformed requests, state erasure and compatibility behavior. 
* \return True on success, false otherwise. 
*/
bool qsctest_csg_boundaries(void);

/** \brief Exercise ACP-backed auto initialization and prediction resistance. 
* \return True on success, false otherwise. 
*/
bool qsctest_csg_auto_seed(void);

/** \brief Detect gross output and state-continuity failures. 
* \return True on success, false otherwise. 
*/
bool qsctest_csg_wellness(void);

/** \brief Execute 256 reproducible valid-input randomized scenarios. 
* \return True on success, false otherwise. 
*/
bool qsctest_csg_fuzz(void);

/** \brief Execute 256 reproducible malformed-request cases. 
* \return True on success, false otherwise. 
*/
bool qsctest_csg_invalid_fuzz(void);

/** 
* \brief Execute all CSG tests directly and sequentially with PASS/FAIL output.
*/
void qsctest_csg_run(void);

#endif
