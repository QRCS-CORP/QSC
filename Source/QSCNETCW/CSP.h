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
