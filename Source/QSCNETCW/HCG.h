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
