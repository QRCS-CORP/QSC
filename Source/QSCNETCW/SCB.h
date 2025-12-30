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

#ifndef QSCNETCW_SCB_H
#define QSCNETCW_SCB_H

#include "Common.h"
#include "..\QSC\scb.h"

namespace QSCNETCW
{
    /// <summary>
    /// A C++/CLI wrapper for the SCB (SHAKE Cost-Based KDF) pseudo-random bytes generator.
    /// 
    /// Usage:
    /// <code>
    /// SCB^ scb = gcnew SCB();
    /// scb->Initialize(seed, seed->Length, info, info->Length, 2, 1);
    /// array&lt;Byte&gt;^ output = gcnew array&lt;Byte&gt;(200);
    /// scb->Generate(output, output->Length);
    /// scb->Dispose();
    /// </code>
    /// </summary>
    public ref class SCB
    {
    public:
        /// <summary>
        /// Constructs an uninitialized SCB instance. You must call <see cref="Initialize"/>
        /// before calling <see cref="Generate"/> or <see cref="Update"/>.
        /// </summary>
        SCB();

        /// <summary>
        /// Destructor that securely disposes of the native SCB state.
        /// </summary>
        ~SCB();

        /// <summary>
        /// Finalizer that disposes of the native SCB state if not already done.
        /// </summary>
        !SCB();

        /// <summary>
        /// Initializes the SCB state with the given seed, optional personalization string,
        /// and cost settings.
        /// </summary>
        /// <param name="seed">A byte array containing the seed (32 or 64 bytes).</param>
        /// <param name="seedLength">The number of bytes in <paramref name="seed"/>.</param>
        /// <param name="info">Optional personalization string. May be null or empty.</param>
        /// <param name="infoLength">Number of bytes in <paramref name="info"/>.</param>
        /// <param name="cpuCost">Number of CPU iterations (must be between <c>QSC_SCB_CPU_MINIMUM</c> and <c>QSC_SCB_CPU_MAXIMUM</c>).</param>
        /// <param name="memCost">Memory cost in MiB (minimum 1, maximum 10000 as per doc, though code suggests <c>QSC_SCB_MEMORY_MAXIMUM=128</c> in the library).</param>
        void Initialize(array<Byte>^ seed, size_t seedLength, array<Byte>^ info, size_t infoLength, size_t cpuCost, size_t memCost);

        /// <summary>
        /// Generates pseudo-random output bytes from the SCB DRBG.
        /// </summary>
        /// <param name="output">A byte array to receive the output data.</param>
        /// <param name="outLength">The number of bytes to generate. Must not exceed the size of <paramref name="output"/>.</param>
        void Generate(array<Byte>^ output, size_t outLength);

        /// <summary>
        /// Updates the SCB with additional seed material.
        /// </summary>
        /// <param name="seed">A byte array containing the new seed material.</param>
        /// <param name="seedLength">Number of bytes in <paramref name="seed"/>.</param>
        void Update(array<Byte>^ seed, size_t seedLength);

        /// <summary>
        /// Disposes the SCB state, zeroizing all sensitive data. The instance becomes invalid after this call.
        /// </summary>
        void Destroy();

    private:
        qsc_scb_state* m_state;
        bool m_isInitialized;
    };
}

#endif
