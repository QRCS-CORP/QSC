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
 * algorithms that are standardized or in the public domain, such as AES
 * and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 * algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 * related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 * parameter selections, and engineering work contained in this software are
 * original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 * cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 * integration into products or services is strictly prohibited without a
 * separate written license agreement executed by QRCS.
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

#ifndef QSC_CJP_H
#define QSC_CJP_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*! \file cjp.h
 *  \brief CPU Jitter Entropy Provider.
 *
 *  \details
 *  The CPU Jitter Provider collects timing variance produced by CPU execution,
 *  memory/cache disturbance, and the active high-resolution platform timer. The
 *  provider follows the QSC entropy-provider interface used by CSP, RDP, and ACP.
 *
 *  The raw timing samples are subjected to online health checks and are never
 *  returned directly. Accepted samples and auxiliary provider material are
 *  concentrated through SHAKE-512 before output is produced.
 */

/*! \def QSC_CJP_SEED_MAX
 *  \brief The maximum number of bytes that can be generated in one provider call.
 */
#define QSC_CJP_SEED_MAX 1024000U

/**
 * \brief Test whether the platform exposes a usable high-resolution timer.
 *
 * \return [bool] Returns true when the CJP timing source passes the timer test.
 */
QSC_EXPORT_API bool qsc_cjp_available(void);

/**
 * \brief Generate an array of random bytes using the CPU jitter entropy provider.
 *
 * \param output: [uint8_t*] Pointer to the output byte array.
 * \param length: [size_t] The number of bytes to generate.
 *
 * \return [bool] Returns true if the entropy generation was successful; false otherwise.
 */
QSC_EXPORT_API bool qsc_cjp_generate(uint8_t* output, size_t length);

/**
 * \brief Generate a random 16-bit unsigned integer using the CPU jitter entropy provider.
 *
 * \return [uint16_t] Returns a random 16-bit unsigned integer.
 */
QSC_EXPORT_API uint16_t qsc_cjp_uint16(void);

/**
 * \brief Generate a random 32-bit unsigned integer using the CPU jitter entropy provider.
 *
 * \return [uint32_t] Returns a random 32-bit unsigned integer.
 */
QSC_EXPORT_API uint32_t qsc_cjp_uint32(void);

/**
 * \brief Generate a random 64-bit unsigned integer using the CPU jitter entropy provider.
 *
 * \return [uint64_t] Returns a random 64-bit unsigned integer.
 */
QSC_EXPORT_API uint64_t qsc_cjp_uint64(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
