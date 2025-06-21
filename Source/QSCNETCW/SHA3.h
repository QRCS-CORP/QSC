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
 * Written by: John Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSCNETCW_SHA3_H
#define QSCNETCW_SHA3_H

#include "Common.h"
#include "..\QSC\sha3.h"

namespace QSCNETCW
{
    /// <summary>
    /// Enumeration of Keccak / SHA3 rates: 128, 256, 512 bits
    /// </summary>
    public enum class KeccakRate : System::UInt32
    {
        /// <summary>
        /// No bit rate was selected
        /// </summary>
        None = qsc_keccak_rate_none,

        /// <summary>
        /// Keccak 128-bit rate (168 bytes)
        /// </summary>
        Rate128 = qsc_keccak_rate_128,

        /// <summary>
        /// Keccak 256-bit rate (136 bytes)
        /// </summary>
        Rate256 = qsc_keccak_rate_256,

        /// <summary>
        /// Keccak 512-bit rate (72 bytes)
        /// </summary>
        Rate512 = qsc_keccak_rate_512
    };

    //-------------------------
    // SHA3
    //-------------------------

    /// <summary>
    /// Static class for an SHA3 process.
    /// </summary>
    public ref class SHA3 abstract sealed
    {
    public:

        /// <summary>
        /// One-shot compute for short form SHA3-128, producing a 16-byte digest.
        /// </summary>
        static void Compute128(array<Byte>^ output, array<Byte>^ message, size_t msgLen);

        /// <summary>
        /// One-shot compute for short form SHA3-256, producing a 32-byte digest.
        /// </summary>
        static void Compute256(array<Byte>^ output, array<Byte>^ message, size_t msgLen);

        /// <summary>
        /// One-shot compute for short form SHA3-512, producing a 64-byte digest.
        /// </summary>
        static void Compute512(array<Byte>^ output, array<Byte>^ message, size_t msgLen);
    };

    //-------------------------
    // SHAKE
    //-------------------------

    /// <summary>
    /// Static class for SHAKE usage.
    /// </summary>
    public ref class SHAKE abstract sealed
    {
    public:

        /// <summary>
        /// Short-form compute for SHAKE-128. 
        /// </summary>
        static void Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen);

        /// <summary>
        /// Short-form compute for SHAKE-256. 
        /// </summary>
        static void Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen);

        /// <summary>
        /// Short-form compute for SHAKE-512. 
        /// </summary>
        static void Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen);
    };

    //-------------------------
    // cSHAKE
    //-------------------------

    /// <summary>
    /// Static class for cSHAKE usage.
    /// </summary>
    public ref class CSHAKE abstract sealed
    {
    public:

        /// <summary>
        /// Short-form cSHAKE-128 with name + custom.
        /// </summary>
        static void Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Short-form cSHAKE-256 with name + custom.
        /// </summary>
        static void Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Short-form cSHAKE-512 with name + custom.
        /// </summary>
        static void Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ key, size_t keyLen, array<Byte>^ name, size_t nameLen, array<Byte>^ custom, size_t custLen);
    };

    //-------------------------
    // KMAC
    //-------------------------

    /// <summary>
    /// Static class for KMAC usage.
    /// </summary>
    public ref class KMAC abstract sealed
    {
    public:

        /// <summary>
        /// Short-form KMAC-128.
        /// </summary>
        static void Compute128(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Short-form KMAC-256.
        /// </summary>
        static void Compute256(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen);

        /// <summary>
        /// Short-form KMAC-512.
        /// </summary>
        static void Compute512(array<Byte>^ output, size_t outLen, array<Byte>^ message, size_t msgLen, array<Byte>^ key, size_t keyLen, array<Byte>^ custom, size_t custLen);
    };
}

#endif // QSCNETCW_SHA3_H
