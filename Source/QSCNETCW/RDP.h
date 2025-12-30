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

#ifndef QSCNETCW_RDP_H
#define QSCNETCW_RDP_H

#include "Common.h"
#include "..\QSC\rdp.h"

namespace QSCNETCW
{
    /// <summary>
    /// A static .NET wrapper for the RDP (RDRAND Entropy Provider) functions, 
    /// providing random bytes or integers using Intel RDRAND if available.
    /// </summary>
    public ref class RDP abstract sealed
    {
    public:

        /// <summary>
        /// Fills the specified output array with random bytes from the RDRAND entropy provider.
        /// </summary>
        /// <param name="output">
        /// A managed byte array to receive the random data.
        /// </param>
        /// <param name="length">
        /// Number of bytes to generate. Must not exceed <c>QSC_RDP_SEED_MAX</c>.
        /// </param>
        /// <returns>
        /// <c>true</c> if random data was successfully generated; otherwise <c>false</c>.
        /// </returns>
        static bool Generate(array<Byte>^ output, size_t length);

        /// <summary>
        /// Generates a random 16-bit unsigned integer from the RDRAND provider.
        /// </summary>
        /// <returns>
        /// A random 16-bit unsigned integer (<c>System::UInt16</c> in .NET).
        /// </returns>
        static System::UInt16 GetUInt16();

        /// <summary>
        /// Generates a random 32-bit unsigned integer from the RDRAND provider.
        /// </summary>
        /// <returns>
        /// A random 32-bit unsigned integer (<c>System::UInt32</c> in .NET).
        /// </returns>
        static System::UInt32 GetUInt32();

        /// <summary>
        /// Generates a random 64-bit unsigned integer from the RDRAND provider.
        /// </summary>
        /// <returns>
        /// A random 64-bit unsigned integer (<c>System::UInt64</c> in .NET).
        /// </returns>
        static System::UInt64 GetUInt64();
    };
}

#endif
