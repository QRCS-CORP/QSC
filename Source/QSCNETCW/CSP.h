/* 2026 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef QSCNETCW_CSP_H
#define QSCNETCW_CSP_H

#include "Common.h"
#include "..\QSC\csp.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper for the QSC Cryptographic System Entropy Provider (CSP).
    /// </summary>
    public ref class CSP abstract sealed
    {
    public:

        /// <summary>
        /// Fills the specified output array with pseudo-random bytes.
        /// </summary>
        /// <param name="output">
        /// A managed byte array to receive the random data.
        /// </param>
        /// <param name="length">
        /// The number of random bytes to generate. Must not exceed <c>QSC_CSP_SEED_MAX</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> on success; otherwise <c>false</c>.
        /// </returns>
        static bool Generate(array<Byte>^ output, size_t length);

        /// <summary>
        /// Generates a pseudo-random 16-bit unsigned integer.
        /// </summary>
        /// <returns>
        /// A 16-bit unsigned integer derived from the system entropy provider.
        /// </returns>
        static UInt16 GetRandomUInt16();

        /// <summary>
        /// Generates a pseudo-random 32-bit unsigned integer.
        /// </summary>
        /// <returns>
        /// A 32-bit unsigned integer derived from the system entropy provider.
        /// </returns>
        static UInt32 GetRandomUInt32();

        /// <summary>
        /// Generates a pseudo-random 64-bit unsigned integer.
        /// </summary>
        /// <returns>
        /// A 64-bit unsigned integer derived from the system entropy provider.
        /// </returns>
        static UInt64 GetRandomUInt64();
    };
}

#endif
