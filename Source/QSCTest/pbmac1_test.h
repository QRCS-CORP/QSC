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
 * - This software includes implementations of cryptographic algorithms that are
 *   standardized or in the public domain, such as AES, SHA-2, SHA-3, HMAC,
 *   PBKDF2, and PBMAC1, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX,
 *   QMAC, and related components, which are proprietary to QRCS.
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

#ifndef QSCTEST_PBMAC1_TEST_H
#define QSCTEST_PBMAC1_TEST_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file pbmac1_test.h
 * \brief Declares PBMAC1 known-answer tests.
 *
 * \details
 * These tests validate the QSC PBMAC1 primitive against the official RFC 9879
 * Appendix A PKCS #12 PBMAC1 test vectors. RFC 9879 obsoletes RFC 9579 and
 * specifies PBMAC1 use inside PKCS #12 syntax. The test vectors are decoded
 * from the RFC PKCS #12 files and use the AuthSafe OCTET STRING contents as
 * the PBMAC1 message, the RFC PBKDF2 salt and iteration count, and the RFC
 * DigestInfo OCTET STRING as the expected MAC.
 *
 * Reference: https://www.rfc-editor.org/rfc/rfc9879.html#appendix-A
 */

/**
 * \brief Tests PBMAC1 with HMAC-SHA2-256 against RFC 9879 Appendix A.1.
 *
 * \return Returns true if the computed MAC, verification path, derived key,
 * and streaming API match the RFC 9879 vector; otherwise, false.
 */
bool qsctest_pbmac1_256_kat(void);

/**
 * \brief Tests PBMAC1 with HMAC-SHA2-512 against RFC 9879 Appendix A.3.
 *
 * \return Returns true if the computed MAC, verification path, derived key,
 * and streaming API match the RFC 9879 vector; otherwise, false.
 */
bool qsctest_pbmac1_512_kat(void);

/**
 * \brief Runs all PBMAC1 known-answer tests.
 */
void qsctest_pbmac1_run(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
