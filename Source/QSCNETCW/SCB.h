/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
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
