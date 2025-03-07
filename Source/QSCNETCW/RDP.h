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
