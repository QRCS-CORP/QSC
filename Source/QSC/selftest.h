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

#ifndef QSC_SELFTEST_H
#define QSC_SELFTEST_H

#include "qsccommon.h"

/*!
 * \file selftest.h
 * \brief Symmetric functions self-test.
 *
 * \details
 * This header provides self-test functions for the cryptographic library's symmetric
 * primitives including AES, ChaCha, CSX, RCS, SHA2, and SHA3 implementations. These tests
 * perform known-answer tests (KATs) to verify correct operation of the implementations.
 * The authenticated CSX-512 self-test verifies ten frozen vectors for the active
 * 20-round default or 40-round extended profile. The RCS-256 and RCS-512
 * self-tests verify ten vectors each for the active 14/21-round default or
 * 22/30-round extended profile. Both families use full 24-round Keccak/KMAC.
 * The AES self-test also verifies independent AES-256-GCM vectors, including
 * multi-block GHASH and authentication-tag rejection.
 */

/*!
 * \brief Tests AES modes, HBA, NIST GCM and independent multi-block GCM KATs.
 *
 * \return [bool] Returns true if the AES test passes.
 */
QSC_EXPORT_API bool qsc_selftest_aes_test(void);

/*!
 * \brief Tests the ChaCha cipher for correct operation.
 *
 * \return [bool] Returns true if the ChaCha test passes.
 */
QSC_EXPORT_API bool qsc_selftest_chacha_test(void);

/*!
 * \brief Tests ten authenticated CSX-512 reference KATs for the active round profile.
 *
 * \return [bool] Returns true if the CSX test passes.
 */
QSC_EXPORT_API bool qsc_selftest_csx_test(void);

/*!
 * \brief Tests ten authenticated KATs each for RCS-256 and RCS-512.
 *
 * \return [bool] Returns true if the RCS test passes.
 */
QSC_EXPORT_API bool qsc_selftest_rcs_test(void);

/*!
 * \brief Tests the SHA2 digests, HKDF and HMAC for correct operation.
 *
 * \return [bool] Returns true if the SHA2 test passes.
 */
QSC_EXPORT_API bool qsc_selftest_sha2_test(void);

/*!
 * \brief Tests the SHA3 digests, SHAKE, cSHAKE, and KMAC for correct operation.
 *
 * \return [bool] Returns true if the SHA3 test passes.
 */
QSC_EXPORT_API bool qsc_selftest_sha3_test(void);

/*!
 * \brief Runs the library self tests.
 *
 * Tests the symmetric primitives with a set of known-answer tests.
 *
 * \return [bool] Returns true if all tests pass successfully.
 */
QSC_EXPORT_API bool qsc_selftest_symmetric_run(void);

#endif
