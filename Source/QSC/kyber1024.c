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

/*
 * Independent 1024-profile compilation of the common Kyber implementation.
 * This file owns one symbol family; the shared code is maintained only in
 * kyberbase.c / kyberbase_avx2.c / kyber.c.
 */
#include "qsccommon.h"

#undef QSC_KYBER_S1K2P512
#undef QSC_KYBER_S3K3P768
#undef QSC_KYBER_S5K4P1024
#undef QSC_KYBER_S6K5P1280
#define QSC_KYBER_S5K4P1024
#define QSC_KYBER_QUALIFIED_PREFIX qsc_kyber1024
#define QSC_KYBER_QUALIFIED_EXPECTED_K 4U
#define QSC_KYBER_QUALIFIED_EXPECTED_ETA1 2U
#define QSC_KYBER_QUALIFIED_EXPECTED_PUBLICKEY_SIZE QSC_KYBER1024_PUBLICKEY_SIZE
#define QSC_KYBER_QUALIFIED_EXPECTED_PRIVATEKEY_SIZE QSC_KYBER1024_PRIVATEKEY_SIZE
#define QSC_KYBER_QUALIFIED_EXPECTED_CIPHERTEXT_SIZE QSC_KYBER1024_CIPHERTEXT_SIZE
#define QSC_KYBER_QUALIFIED_EXPECTED_SHAREDSECRET_SIZE QSC_KYBER1024_SHAREDSECRET_SIZE

#include "kyber1024.h"
#include "kyber_parameter_impl.h"

#undef QSC_KYBER_QUALIFIED_EXPECTED_SHAREDSECRET_SIZE
#undef QSC_KYBER_QUALIFIED_EXPECTED_CIPHERTEXT_SIZE
#undef QSC_KYBER_QUALIFIED_EXPECTED_PRIVATEKEY_SIZE
#undef QSC_KYBER_QUALIFIED_EXPECTED_PUBLICKEY_SIZE
#undef QSC_KYBER_QUALIFIED_EXPECTED_ETA1
#undef QSC_KYBER_QUALIFIED_EXPECTED_K
#undef QSC_KYBER_QUALIFIED_PREFIX
