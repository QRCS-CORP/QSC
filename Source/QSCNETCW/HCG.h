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

#ifndef QSCNETCW_HCG_H
#define QSCNETCW_HCG_H

#include "Common.h"
#include "..\QSC\hcg.h"

namespace QSCNETCW
{
    /// <summary>
    /// Managed wrapper for the HCG (HMAC-based Custom Generator).
    /// </summary>
    public ref class HCG
    {
    public:
        /// <summary>
        /// Allocates the native state for the HCG generator.
        /// </summary>
        HCG();

        /// <summary>
        /// Destructor that calls <see cref="Destroy"/> to free native resources.
        /// </summary>
        ~HCG();

        /// <summary>
        /// Finalizer that calls <see cref="Destroy"/> if the destructor was not invoked.
        /// </summary>
        !HCG();

        /// <summary>
        /// Initializes the generator with a seed, optional info, and predictive resistance flag.
        /// </summary>
        /// <param name="seed">Seed array (32 or 64 bytes).</param>
        /// <param name="seedLength">Number of bytes in <paramref name="seed"/>.</param>
        /// <param name="info">Optional info array.</param>
        /// <param name="infoLength">Number of bytes in <paramref name="info"/>.</param>
        /// <param name="pres">Enable predictive resistance.</param>
        /// <returns><c>true</c> on success; otherwise <c>false</c>.</returns>
        bool Initialize(array<Byte>^ seed, size_t seedLength, array<Byte>^ info, size_t infoLength, bool pres);

        /// <summary>
        /// Generates pseudo-random bytes into the output array.
        /// </summary>
        /// <param name="output">A byte array receiving the random data.</param>
        /// <param name="outputLength">Number of bytes to generate.</param>
        /// <returns><c>true</c> on success; otherwise <c>false</c>.</returns>
        bool Generate(array<Byte>^ output, size_t outputLength);

        /// <summary>
        /// Updates the generator with new seed material.
        /// </summary>
        /// <param name="seed">Seed array.</param>
        /// <param name="seedLength">Number of bytes in <paramref name="seed"/>.</param>
        /// <returns><c>true</c> on success; otherwise <c>false</c>.</returns>
        bool Update(array<Byte>^ seed, size_t seedLength);

        /// <summary>
        /// Disposes the generator state, clearing sensitive data.
        /// </summary>
        void Destroy();

    private:
        qsc_hcg_state* m_state;
        bool m_isInitialized;
    };
}

#endif
