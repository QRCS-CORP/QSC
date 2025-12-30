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

#ifndef QSCNETCW_CSG_H
#define QSCNETCW_CSG_H

#include "Common.h"
#include "..\QSC\csg.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a managed wrapper for the QSC Custom SHAKE Generator (CSG), 
    /// an extensible-output-function-based pseudo-random byte generator.
    /// </summary>
    public ref class CSG
    {
    public:
        /// <summary>
        /// Initializes a new instance of the <c>CSG</c> class and allocates native state.
        /// </summary>
        CSG();

        /// <summary>
        /// Destructor that disposes the native CSG state.
        /// </summary>
        ~CSG();

        /// <summary>
        /// Finalizer that disposes the native CSG state if not already done.
        /// </summary>
        !CSG();

        /// <summary>
        /// Initializes the CSG with a seed and optional personalization string.
        /// </summary>
        /// <param name="seed">
        /// A managed byte array used as the seed. Must be 32 bytes (cSHAKE-256) or 64 bytes (cSHAKE-512).
        /// </param>
        /// <param name="info">
        /// A managed byte array for optional personalization data. May be <c>null</c>.
        /// </param>
        /// <param name="predres">
        /// If <c>true</c>, predictive resistance is enabled, injecting extra randomness periodically.
        /// </param>
        /// <returns>
        /// <c>true</c> on successful initialization; otherwise <c>false</c>.
        /// </returns>
        bool Initialize(array<Byte>^ seed, array<Byte>^ info, bool predres);

        /// <summary>
        /// Generates pseudo-random bytes and writes them into the specified output buffer.
        /// </summary>
        /// <param name="output">
        /// A managed byte array to receive the pseudo-random data.
        /// </param>
        /// <param name="otplen">
        /// The number of bytes to write into the <paramref name="output"/> array.
        /// </param>
        /// <returns>
        /// <c>true</c> if the data was successfully generated; otherwise <c>false</c>.
        /// </returns>
        bool Generate(array<Byte>^ output, size_t otplen);

        /// <summary>
        /// Updates the generator's state with additional seed material.
        /// </summary>
        /// <param name="seed">
        /// A managed byte array containing new seed material to inject into the generator.
        /// </param>
        /// <returns>
        /// <c>true</c> if the update was successful; otherwise <c>false</c>.
        /// </returns>
        bool Update(array<Byte>^ seed);

        /// <summary>
        /// Disposes the native CSG state, clearing all sensitive data.
        /// </summary>
        void Destroy();

    private:
        qsc_csg_state* m_state;
        bool m_isInitialized;
    };
}

#endif
