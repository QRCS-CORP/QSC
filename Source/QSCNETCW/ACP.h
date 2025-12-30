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

#ifndef QSCNETCW_ACP_H
#define QSCNETCW_ACP_H

#include "Common.h"
#include "..\QSC\acp.h"

namespace QSCNETCW 
{
    /// <summary>
    /// Provides a managed wrapper for the Auto Entropy Collection Provider (ACP) from the QSC cryptographic library.
    /// 
    /// The ACP aggregates entropy from various system sources including hardware randomness (via RDRAND),
    /// system statistics, and platform-specific providers (e.g., CryptGenRandom on Windows and /dev/urandom on POSIX systems).
    /// The collected entropy is processed using the cSHAKE-512 algorithm to generate cryptographically secure pseudorandom data.
    /// </summary>
    public ref class ACP abstract sealed
    {
    public:

        /// <summary>
        /// Generates cryptographically secure random bytes and stores them in the specified buffer.
        /// </summary>
        /// <param name="buffer">A managed array of bytes to receive the random data.</param>
        /// <param name="length">The number of random bytes to generate and store in the buffer.</param>
        /// <returns>
        /// A boolean indicating success (<c>true</c>) or failure (<c>false</c>).
        /// </returns>
        static bool GenerateRandomBytes(array<Byte>^ buffer, size_t length);

        /// <summary>
        /// Generates a cryptographically secure random 16-bit unsigned integer.
        /// </summary>
        /// <returns>A 16-bit unsigned integer derived from high-quality random data.</returns>
        static uint16_t GetRandomUInt16();

        /// <summary>
        /// Generates a cryptographically secure random 32-bit unsigned integer.
        /// </summary>
        /// <returns>A 32-bit unsigned integer derived from high-quality random data.</returns>
        static uint32_t GetRandomUInt32();

        /// <summary>
        /// Generates a cryptographically secure random 64-bit unsigned integer.
        /// </summary>
        /// <returns>A 64-bit unsigned integer derived from high-quality random data.</returns>
        static uint64_t GetRandomUInt64();
    };
}

#endif
