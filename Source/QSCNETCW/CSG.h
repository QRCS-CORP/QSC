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
